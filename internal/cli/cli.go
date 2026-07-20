// Package cli implements the interactive command-line front end.
package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"cli-login-system/internal/auth"
	"cli-login-system/internal/models"
	"cli-login-system/internal/session"

	"github.com/chzyer/readline"
)

type CLI struct {
	auth      *auth.Service
	authStore *auth.Store
	sessions  *session.Manager

	rl          *readline.Instance
	currentUser *models.User
	sessionTok  string
}

func New(authSvc *auth.Service, authStore *auth.Store, sessions *session.Manager, historyFile string) (*CLI, error) {
	rl, err := readline.NewEx(&readline.Config{
		Prompt:          "login> ",
		HistoryFile:     historyFile,
		AutoComplete:    loggedOutCompleter,
		InterruptPrompt: "^C",
		EOFPrompt:       "exit",
	})
	if err != nil {
		return nil, err
	}
	return &CLI{auth: authSvc, authStore: authStore, sessions: sessions, rl: rl}, nil
}

func (c *CLI) Close() {
	c.rl.Close()
}

var loggedOutCompleter = readline.NewPrefixCompleter(
	readline.PcItem("register"),
	readline.PcItem("login"),
	readline.PcItem("help"),
	readline.PcItem("exit"),
)

var loggedInCompleter = readline.NewPrefixCompleter(
	readline.PcItem("whoami"),
	readline.PcItem("enable-2fa"),
	readline.PcItem("disable-2fa"),
	readline.PcItem("logout"),
	readline.PcItem("help"),
)

// Run starts the REPL loop until the user exits or input closes.
func (c *CLI) Run() {
	fmt.Println("=== CLI Login System ===")
	fmt.Println("Type 'help' for available commands.")

	for {
		c.updatePrompt()
		line, err := c.rl.Readline()
		if err != nil { // io.EOF (Ctrl-D) or readline.ErrInterrupt (Ctrl-C)
			if errors.Is(err, io.EOF) || errors.Is(err, readline.ErrInterrupt) {
				fmt.Println("\nGoodbye.")
				return
			}
			fmt.Println("input error:", err)
			return
		}

		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		cmd := fields[0]
		args := fields[1:]

		if c.sessionExpiredCheck() {
			continue
		}

		if c.currentUser == nil {
			if !c.dispatchLoggedOut(cmd, args) {
				return
			}
		} else {
			if !c.dispatchLoggedIn(cmd, args) {
				return
			}
		}
	}
}

func (c *CLI) updatePrompt() {
	if c.currentUser != nil {
		c.rl.SetPrompt(fmt.Sprintf("%s> ", c.currentUser.Username))
		c.rl.Config.AutoComplete = loggedInCompleter
	} else {
		c.rl.SetPrompt("login> ")
		c.rl.Config.AutoComplete = loggedOutCompleter
	}
}

// sessionExpiredCheck logs the user out if their session token has expired,
// printing a notice. Returns true if it just logged the user out.
func (c *CLI) sessionExpiredCheck() bool {
	if c.currentUser == nil || c.sessionTok == "" {
		return false
	}
	if _, err := c.sessions.Validate(context.Background(), c.sessionTok); err != nil {
		fmt.Println("Your session has expired. Please log in again.")
		c.currentUser = nil
		c.sessionTok = ""
		return true
	}
	return false
}

func (c *CLI) dispatchLoggedOut(cmd string, args []string) bool {
	switch cmd {
	case "register":
		c.cmdRegister()
	case "login":
		c.cmdLogin()
	case "help":
		c.printHelpLoggedOut()
	case "exit", "quit":
		fmt.Println("Goodbye.")
		return false
	default:
		fmt.Printf("Unknown command %q. Type 'help' for available commands.\n", cmd)
	}
	return true
}

func (c *CLI) dispatchLoggedIn(cmd string, args []string) bool {
	switch cmd {
	case "whoami":
		c.printUserDetails()
	case "enable-2fa":
		c.cmdEnable2FA()
	case "disable-2fa":
		c.cmdDisable2FA()
	case "logout":
		c.cmdLogout()
	case "help":
		c.printHelpLoggedIn()
	case "exit", "quit":
		c.cmdLogout()
		fmt.Println("Goodbye.")
		return false
	default:
		fmt.Printf("Unknown command %q. Type 'help' for available commands.\n", cmd)
	}
	return true
}

func (c *CLI) printHelpLoggedOut() {
	fmt.Println(`Available commands:
  register   Create a new user account
  login      Log in with username/password (+ TOTP if enabled)
  help       Show this message
  exit       Quit the program`)
}

func (c *CLI) printHelpLoggedIn() {
	fmt.Println(`Available commands:
  whoami       Show current user details
  enable-2fa   Enable TOTP-based two-factor authentication
  disable-2fa  Disable two-factor authentication
  logout       End the current session
  help         Show this message
  exit         Log out and quit the program`)
}

func (c *CLI) readLine(prompt string) (string, error) {
	c.rl.SetPrompt(prompt)
	line, err := c.rl.Readline()
	return strings.TrimSpace(line), err
}

func (c *CLI) readPassword(prompt string) (string, error) {
	pw, err := c.rl.ReadPassword(prompt)
	return strings.TrimSpace(string(pw)), err
}

func (c *CLI) cmdRegister() {
	username, err := c.readLine("username: ")
	if err != nil {
		return
	}
	password, err := c.readPassword("password: ")
	if err != nil {
		return
	}
	confirm, err := c.readPassword("confirm password: ")
	if err != nil {
		return
	}
	if password != confirm {
		fmt.Println("✗ Passwords do not match.")
		return
	}

	if _, err := c.auth.Register(context.Background(), username, password); err != nil {
		fmt.Println("✗ Registration failed:", friendlyErr(err))
		return
	}
	fmt.Printf("✓ Account %q created. You can now log in.\n", username)
}

func (c *CLI) cmdLogin() {
	username, err := c.readLine("username: ")
	if err != nil {
		return
	}
	password, err := c.readPassword("password: ")
	if err != nil {
		return
	}

	user, err := c.auth.Login(context.Background(), username, password, "")
	if errors.Is(err, auth.ErrTOTPRequired) {
		code, err := c.readLine("2FA code: ")
		if err != nil {
			return
		}
		user, err = c.auth.Login(context.Background(), username, password, code)
		if err != nil {
			fmt.Println("✗ Login failed:", friendlyErr(err))
			return
		}
	} else if err != nil {
		fmt.Println("✗ Login failed:", friendlyErr(err))
		return
	}

	sess, err := c.sessions.Create(context.Background(), user.ID)
	if err != nil {
		fmt.Println("✗ Could not start session:", err)
		return
	}
	c.currentUser = user
	c.sessionTok = sess.Token
	fmt.Printf("✓ Welcome, %s!\n", user.Username)
	c.printUserDetails()
}

func (c *CLI) cmdLogout() {
	if c.sessionTok != "" {
		_ = c.sessions.Destroy(context.Background(), c.sessionTok)
	}
	fmt.Println("✓ Logged out.")
	c.currentUser = nil
	c.sessionTok = ""
}

func (c *CLI) cmdEnable2FA() {
	if c.currentUser.TOTPEnabled {
		fmt.Println("✗ 2FA is already enabled.")
		return
	}
	secret, url, err := c.auth.EnableTOTP(context.Background(), c.currentUser)
	if err != nil {
		fmt.Println("✗", friendlyErr(err))
		return
	}
	fmt.Println("Scan this into Google Authenticator (or add manually):")
	fmt.Println("  Secret:", secret)
	fmt.Println("  otpauth URL:", url)
	code, err := c.readLine("Enter the 6-digit code to confirm: ")
	if err != nil {
		return
	}
	if err := c.auth.ConfirmTOTP(context.Background(), c.currentUser, secret, code); err != nil {
		fmt.Println("✗ Could not enable 2FA:", friendlyErr(err))
		return
	}
	c.currentUser.TOTPEnabled = true
	fmt.Println("✓ 2FA enabled.")
}

func (c *CLI) cmdDisable2FA() {
	if err := c.auth.DisableTOTP(context.Background(), c.currentUser); err != nil {
		fmt.Println("✗", friendlyErr(err))
		return
	}
	c.currentUser.TOTPEnabled = false
	fmt.Println("✓ 2FA disabled.")
}

func (c *CLI) printUserDetails() {
	u := c.currentUser
	fmt.Println("--- Account details ---")
	fmt.Println("Username:          ", u.Username)
	fmt.Println("Registered:        ", u.CreatedAt.Format(time.RFC1123))
	if u.TOTPEnabled {
		fmt.Println("2FA:               enabled")
	} else {
		fmt.Println("2FA:               disabled")
	}
	if sess, err := c.sessions.Validate(context.Background(), c.sessionTok); err == nil {
		fmt.Println("Session expires:   ", sess.ExpiresAt.Format(time.RFC1123))
	}
	if u.LastLogin != nil {
		fmt.Println("Last login:        ", u.LastLogin.Format(time.RFC1123))
	} else {
		fmt.Println("Last login:         (first login)")
	}
}

func friendlyErr(err error) string {
	return err.Error()
}
