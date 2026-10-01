package mcp

import (
	"context"
	"fmt"
)

// dispatch runs one tool by name. A name that is not registered is a protocol
// error: the client asked for a tool this server does not have, which is a
// different failure from a tool that ran and was refused.
func (s *server) dispatch(ctx context.Context, name string, a args) (string, any, error) {
	switch name {
	case "session_open":
		return s.open(ctx, a)
	case "session_list":
		return s.list(ctx)
	case "session_send":
		if s.readOnly {
			return "", nil, unknownTool(name)
		}
		return s.send(ctx, a)
	case "session_read":
		return s.read(ctx, a)
	case "session_interrupt":
		if s.readOnly {
			return "", nil, unknownTool(name)
		}
		return s.interrupt(ctx, a)
	case "session_close":
		if s.readOnly {
			return "", nil, unknownTool(name)
		}
		return s.close(ctx, a)
	default:
		return "", nil, unknownTool(name)
	}
}

func unknownTool(name string) error {
	return &wireError{
		Code:    codeMethodNotFound,
		Message: "there is no tool named " + name + " on this server",
	}
}

// definitions is the tool list.
//
// In read-only mode only session_list and session_read are registered, because
// read-only means the target is left as it was found and opening a session is a
// change to it. The write tools are absent rather than refused at call time: a
// model that cannot see a tool does not try it and cannot be surprised by a
// refusal.
func (s *server) definitions() []toolDef {
	tools := []toolDef{
		{
			Name:        "session_list",
			Title:       "List sessions",
			Description: "List the sessions in the local catalog, with a probe read on each to find out whether it is still running. A probe on a remote target that needs approval reports that instead of a state.",
			InputSchema: s.schema(nil),
			Annotations: &annotations{ReadOnlyHint: true, IdempotentHint: true, OpenWorldHint: true},
		},
		{
			Name:        "session_read",
			Title:       "Read output",
			Description: "Read what a session has printed, continuing from the last read. Use wait to block until a prompt, a pattern or a byte count. Without a cursor it returns new output; with one it re-reads that stretch and does not move the saved position.",
			InputSchema: s.schema(map[string]any{
				sessionProp: s.stringProp("Which session to read, by alias or by id."),
				"cursor":    s.uintProp("Byte offset to re-read from. Optional: a re-read does not advance the saved cursor.", 0),
				"max_bytes": s.uintProp("Largest page to return. Optional.", 1),
				"wait":      s.waitProp(fmt.Sprintf(readWaitFallback, defaultReadWaitMS)),
			}, sessionProp),
			Annotations: &annotations{ReadOnlyHint: true, OpenWorldHint: true},
		},
	}

	if s.readOnly {
		return tools
	}

	tools = append(tools,
		toolDef{
			Name:        "session_open",
			Title:       "Open a shell session",
			Description: "Create a shell session on a target and return its first output. It does not attach, so the session stays writable from here. Give it a name to refer to it later; without one it is called agent-1, agent-2 and so on.",
			InputSchema: s.schema(map[string]any{
				"name":  s.stringProp("Alias for this session, for example build. Optional: one is assigned when it is absent."),
				"shell": s.stringProp("Command to run instead of the login shell, for example bash -l. Optional: the target picks the login shell. The target validates it."),
			}),
			Annotations: &annotations{OpenWorldHint: true},
		},
		toolDef{
			Name:  "session_send",
			Title: "Type into a session",
			Description: "Type into a session nobody is attached to and return what those keystrokes produced. " +
				"The command must end with a real newline, as in \"echo hi\\n\", or the shell waits for more input and nothing runs. " +
				"Refused while a person is attached, so a human and a model cannot fight over one session. " +
				"Without a wait condition it waits for the output to go quiet; a long run needs session_interrupt.",
			InputSchema: s.schema(map[string]any{
				sessionProp: s.stringProp("Which session to type into, by alias or by id."),
				"data": map[string]any{
					"type": "string",
					"description": "The text or keys to type, sent as it stands. " +
						"End a command with a real newline, as in \"echo hi\\n\"; nothing is added on its own, " +
						"so a command without one leaves the shell waiting. " +
						"Stop a running command with session_interrupt rather than by typing a control character.",
				},
				"escapes": map[string]any{
					"type": "boolean",
					"description": "Read data as a key sequence instead of typing it as it stands. " +
						"Optional, false when absent. When true only \\n, \\r, \\t, \\xHH and \\\\ are recognized and " +
						"anything else is an error, so leave it off for a command that holds a real backslash, " +
						"such as a regex, a sed script or a Windows path.",
					"default": false,
				},
				"secret": map[string]any{
					"type": "boolean",
					"description": "Refuse the write unless the terminal is not echoing. " +
						"Set it for a password, a token or a key: the target checks the terminal at the " +
						"moment it writes, and writes nothing when the bytes would echo into the session's " +
						"scrollback and output log. " +
						"It is refused, rather than written and warned about, in three cases: the terminal " +
						"echoes; the terminal is in raw mode, which is what a full-screen program or a nested " +
						"terminal produces and where the far end cannot be checked; or the state could not be " +
						"read at all. Each refusal says which, and a human is the way out. " +
						"Leave it off when you are not sure: an ordinary prompt with this set is refused, " +
						"which is the safe direction to be wrong in.",
					"default": false,
				},
				"wait": s.waitProp(fmt.Sprintf(sendWaitFallback, defaultSendIdleMS, defaultSendWaitMS)),
			}, sessionProp, "data"),
			Annotations: &annotations{DestructiveHint: true, OpenWorldHint: true},
		},
		toolDef{
			Name:        "session_interrupt",
			Title:       "Interrupt a running command",
			Description: "Send Ctrl-C to a session, which stops the command it is running, and return what the shell said about it. Use it instead of typing control characters into session_send.",
			InputSchema: s.schema(map[string]any{
				sessionProp: s.stringProp("Which session to interrupt, by alias or by id."),
			}, sessionProp),
			Annotations: &annotations{DestructiveHint: true, OpenWorldHint: true},
		},
		toolDef{
			Name:        "session_close",
			Title:       "Close a session",
			Description: "End a session. It cannot be reopened, so this is not the way to refresh a shell: call session_open for a new one.",
			InputSchema: s.schema(map[string]any{
				sessionProp: s.stringProp("Which session to close, by alias or by id."),
			}, sessionProp),
			Annotations: &annotations{DestructiveHint: true, OpenWorldHint: true},
		},
	)
	return tools
}

// sessionProp names the session argument. It is the same key in every tool that
// works on an existing session, so a model reads one description for it.
const sessionProp = "session"

// schema builds the input schema. The peer property is added only when the
// process serves more than one target: with one target there is nothing to
// choose, and offering the choice would let a model pick the machine.
//
// session_list is the exception. It reports every session the catalog knows, so a
// peer argument would be read and then ignored, which is worse than not offering
// it.
func (s *server) schema(props map[string]any, required ...string) map[string]any {
	if props == nil {
		props = map[string]any{}
	}
	if s.multiPeer() && len(props) > 0 {
		props["peer"] = s.stringProp("Which target, one of: " + joinNames(s.peerNames()))
	}
	if len(required) == 0 {
		return map[string]any{"type": "object", "properties": props}
	}
	return map[string]any{"type": "object", "properties": props, "required": required}
}

func (s *server) stringProp(desc string) map[string]any {
	return map[string]any{"type": "string", "description": desc}
}

func (s *server) uintProp(desc string, min float64) map[string]any {
	return map[string]any{"type": "integer", "minimum": min, "description": desc}
}

// The two fallbacks differ, so each tool states its own instead of sharing a
// sentence that would describe the other one.
const (
	readWaitFallback = "without a match or an idle rule this call waits %d ms for new output and then returns, " +
		"empty or not. A session that is still running can be waited on longer with match or idle_ms."
	sendWaitFallback = "without a match or an idle rule, send waits for the output to go quiet after %d ms " +
		"and gives up after %d ms."
)

// waitProp is the shape of the wait argument, which read and send share. They
// share the properties but not the fallback, so the caller states what happens
// when it passes no condition at all.
func (s *server) waitProp(fallback string) map[string]any {
	props := map[string]any{
		"idle_ms": map[string]any{
			"type":        "integer",
			"minimum":     0,
			"description": "Return once the output has been quiet this long.",
		},
		"max_bytes": map[string]any{
			"type":        "integer",
			"minimum":     1,
			"description": "Return once this many bytes have arrived.",
		},
		"wait_ms": map[string]any{
			"type":        "integer",
			"minimum":     0,
			"maximum":     maxWaitMS,
			"description": fmt.Sprintf("Never wait longer than this. A read on a target is parked at most %d ms.", maxWaitMS),
		},
	}
	props["match"] = map[string]any{
		"type": "string",
		"description": "RE2 pattern to wait for, for example \"[Pp]assword:\" or \"^\\\\S+@\\\\S+$\" for a prompt. " +
			"Use it instead of idle_ms when the shell is expected to ask something.",
	}
	return map[string]any{"type": "object", "properties": props,
		"description": "When to return. Optional: " + fallback}
}

func joinNames(names []string) string {
	out := ""
	for i, n := range names {
		switch {
		case i == 0:
			out = n
		case i == len(names)-1:
			out += " and " + n
		default:
			out += ", " + n
		}
	}
	return out
}
