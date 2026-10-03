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
		// The fan-out only exists when the caller asked for it. Without `peers` this
		// is the single-target path, unchanged, so a server serving one machine
		// behaves exactly as it did before.
		if a.has("peers") {
			return s.listMany(ctx, a)
		}
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
	case "file_read":
		// Registered only when a root is configured, so reaching here means it is. The
		// check is repeated anyway, because dispatch is reachable by name and the
		// registration is not the only thing that decides.
		if !s.fileRootConfigured {
			return "", nil, unknownTool(name)
		}
		return s.fileRead(ctx, a)
	case "file_write":
		// Both gates, and they are not the same gate. Registration is what a model
		// sees; this is what stops a call that names the tool anyway. A tool that is
		// merely absent can still be invoked by name, so the read-only refusal cannot
		// live only in the tool list.
		if !s.fileRootConfigured || s.readOnly {
			return "", nil, unknownTool(name)
		}
		return s.fileWrite(ctx, a)
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
			Description: "List the sessions in the local catalog, with a probe read on each to find out whether it is still running. A probe on a remote target that needs approval reports that instead of a state. Pass peers to ask several machines at once; without it only the default target is asked.",
			InputSchema: s.schemaNoPeerArg(map[string]any{
				"peers": map[string]any{
					"type":  []string{"string", "array"},
					"items": map[string]any{"type": "string"},
					"description": "Which machines to ask, by the names --peer takes. " +
						"\"all\" asks every machine this server serves. Omit it and only the " +
						"default target is asked — omitting is not the same as asking for all. " +
						"They are probed at the same time, bounded to a few at once, so one " +
						"unreachable machine no longer holds up the others. Within one machine " +
						"the probes stay in sequence: a machine with many sessions does not " +
						"get many reads past its approval gate at once. A machine that cannot " +
						"be reached is reported and the rest of the answer still comes back. " +
						"Only reading tools take this; send, interrupt, close and open stay on " +
						"one machine, because broadcasting keystrokes is not reversible.",
				},
			}),
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

	// The file tools exist only where the operator configured a root. Absent rather
	// than refused: a model that cannot see a tool does not try it, and cannot be
	// surprised by a refusal it has to interpret.
	//
	// **This machine's configuration.** A session on a remote peer belongs to that
	// machine's operator, whose root this process cannot see, so a remote session
	// without one answers `unavailable` at call time — which is deliberately a
	// different answer from "that file is not there".
	if s.fileRootConfigured {
		tools = append(tools,
			toolDef{
				Name:  "file_read",
				Title: "Read a file",
				Description: "Read a file from the directory this session is rooted at, " +
					"instead of shelling out to cat. Returns the bytes as they are, " +
					"with the file's size and the digest of the whole file, so a later " +
					"file_write can pass that digest and be refused if the content moved on. " +
					"offset and max_bytes page through a large file; without them you get the first " +
					"page and truncated says whether there is more. " +
					"Each call is one operation and needs one approval.",
				InputSchema: s.schema(map[string]any{
					sessionProp: s.stringProp("Which session's root to read in, by alias or by id."),
					"path":      s.stringProp("File to read, relative to the session's root. An absolute path is refused."),
					"root":      s.stringProp("Narrow the session's root to this subdirectory for this call. Optional; it can only narrow."),
					"offset":    s.uintProp("Byte offset to start at. Optional; the default is the beginning.", 0),
					"max_bytes": s.uintProp("Largest page to return. Optional.", 1),
				}, sessionProp),
				Annotations: &annotations{ReadOnlyHint: true, OpenWorldHint: true},
			},
		)
		if !s.readOnly {
			tools = append(tools, toolDef{
				Name:  "file_write",
				Title: "Write a file",
				Description: "Create or replace a file in the directory this session is rooted at. " +
					"content is base64. mode says whether to create (which fails if the file is already there, " +
					"so it never overwrites by accident) or replace (which fails if it is not). " +
					"expected_sha256 is the digest file_read returned earlier: pass it and the write is " +
					"refused if the content changed since, so two writers cannot silently undo each other. " +
					"The write is atomic, and the file keeps the permissions it already had. " +
					"\n\nEach call is one operation and needs one approval, and the approval is spent " +
					"whether or not the write succeeds — a refusal still uses it up. If a write comes back " +
					"failed, do not simply try again: the reason says whether the content changed, the path " +
					"was refused, or an operator has to approve the next attempt.",
				InputSchema: s.schema(map[string]any{
					sessionProp: s.stringProp("Which session's root to write in, by alias or by id."),
					"path":      s.stringProp("File to write, relative to the session's root. An absolute path is refused."),
					"root":      s.stringProp("Narrow the session's root to this subdirectory for this call. Optional; it can only narrow."),
					"mode": map[string]any{
						"type": "string",
						"enum": []string{"create", "replace"},
						"description": "create fails if the file is there; replace fails if it is not. " +
							"There is no mode that does both.",
					},
					"content": map[string]any{
						"type":        "string",
						"description": "The bytes to write, base64 encoded. Text is not guessed: base64 what you mean.",
					},
					"expected_sha256": map[string]any{
						"type":        "string",
						"description": "Optional. The digest file_read returned for this path. The write is refused if it no longer matches, so a file that changed under you is not overwritten.",
					},
				}, sessionProp),
				Annotations: &annotations{OpenWorldHint: true},
			})
		}
	}

	if s.readOnly {
		return tools
	}

	tools = append(tools,
		toolDef{
			Name:        "session_open",
			Title:       "Open a shell session",
			Description: "Create a shell session on a target and return its first output. It does not attach, so the session stays writable from here. Give it a name to refer to it later; without one it is called agent-1, agent-2 and so on." + s.rootHint(),
			InputSchema: s.schema(s.openProps(), s.openRequired()...),
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
	return objectSchema(props, required)
}

// schemaNoPeerArg is schema without the automatic peer argument, for a tool that
// reports every target anyway. A peer argument there would be read and then ignored,
// which is worse than not offering it.
//
// session_list is that case: it lists the local catalog, which already holds every
// target's sessions, so `peers` chooses which of them to *probe* rather than which
// to report. Both exist, and they mean different things.
func (s *server) schemaNoPeerArg(props map[string]any, required ...string) map[string]any {
	if props == nil {
		props = map[string]any{}
	}
	return objectSchema(props, required)
}

func objectSchema(props map[string]any, required []string) map[string]any {
	if len(required) == 0 {
		return map[string]any{"type": "object", "properties": props}
	}
	return map[string]any{"type": "object", "properties": props, "required": required}
}

func (s *server) stringProp(desc string) map[string]any {
	return map[string]any{"type": "string", "description": desc}
}

// openProps is session_open's schema.
//
// `root` is added only where file tools exist. A root argument that silently does
// nothing is worse than no argument at all: a model would pass one and believe it had
// narrowed something. Built here rather than passed as a nil map, because a nil entry
// marshals to `"root": null` and an empty required name marshals to `""` — both of
// which are a changed schema rather than an absent one.
func (s *server) openProps() map[string]any {
	props := map[string]any{
		"name":  s.stringProp("Alias for this session, for example build. Optional: one is assigned when it is absent."),
		"shell": s.stringProp("Command to run instead of the login shell, for example bash -l. Optional: the target picks the login shell. The target validates it."),
	}
	if s.fileRootConfigured {
		props["root"] = s.stringProp("Directory the file tools work in for this session, relative to " +
			"the one the operator configured. Optional, and it can only narrow: a path outside the " +
			"operator's directory is refused. Every later file_read and file_write on this session " +
			"starts here.")
	}
	return props
}

// openRequired is session_open's required list, which never includes an optional
// argument — so it is empty unless a caller made root required, which none does.
func (s *server) openRequired() []string { return nil }

// rootHint is the sentence added to session_open's description where a root exists.
func (s *server) rootHint() string {
	if !s.fileRootConfigured {
		return ""
	}
	return " root narrows the directory the file tools work in, for this session and everything " +
		"later done on it; it can only narrow, so a root outside the operator's is refused."
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
