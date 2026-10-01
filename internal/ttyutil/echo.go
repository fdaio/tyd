package ttyutil

import "fmt"

// EchoState is the part of a terminal's line discipline that decides what a
// keystroke written to it looks like once it arrives.
type EchoState struct {
	// Echo is the ECHO bit: whether the line discipline echoes the bytes it
	// receives.
	Echo bool
	// Icanon is ICANON: whether input is delivered a line at a time rather than a
	// byte at a time.
	Icanon bool
}

// InputMode is what those two bits add up to for someone about to type.
type InputMode string

const (
	// InputEcho means the line discipline echoes, so every byte appears as it is
	// written and is recorded by whatever watches the terminal.
	InputEcho InputMode = "echo"

	// InputSecretLikely means a program turned echo off and is reading a line
	// itself, which is what a password prompt looks like from outside.
	InputSecretLikely InputMode = "secret_likely"

	// InputAppManaged means neither bit is set: the program owns echo and line
	// editing entirely. A full-screen program, and any nested terminal.
	InputAppManaged InputMode = "app_managed"
)

// ErrNotATerminal is what reading the state of a descriptor that is not a
// terminal returns. It is deliberately an error rather than a zero state: a
// caller that read "unknown" as "not echoing" would allow a secret it cannot
// verify.
var ErrNotATerminal = fmt.Errorf("not a terminal")

// InputMode classifies the state.
//
// A shell with readline turns the kernel ECHO bit off at an ordinary prompt and
// echoes in userspace, so ECHO alone says nothing about whether the input is a
// secret. What separates the two is ICANON: readline reads a byte at a time with
// ICANON off, while a program that turned echo off for a secret leaves line
// delivery on and reads the line itself.
func (s EchoState) InputMode() InputMode {
	switch {
	case s.Echo:
		return InputEcho
	case s.Icanon:
		return InputSecretLikely
	default:
		return InputAppManaged
	}
}

// String names the mode the way a person reading a result would.
func (m InputMode) String() string { return string(m) }
