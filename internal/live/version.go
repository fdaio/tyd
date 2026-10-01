package live

// The dataplane between a daemon and a live agent is a unix socket with no
// handshake. That matters for one request and one only: a flag the agent does not
// understand is ignored rather than refused, so a daemon cannot tell an old agent
// from a new one by sending the flag and waiting to be told no.
//
// For a keystroke, ignoring an unknown flag is harmless. For a request to write a
// secret, it is the whole failure this exists to prevent: the bytes go to the PTY
// in the clear and the promise the caller was given is false. So the agent stamps
// what it is on the frames it sends, and the daemon refuses a secret write until it
// has seen a new enough agent.

// AgentVersion is what this build speaks to a live agent.
//
// It is learned by observation rather than negotiated: the first read or send on a
// session says what the agent is. There is no way to ask first, because asking is
// itself a frame an old agent would not understand.
const AgentVersion = 2

// MinSecretVersion is the oldest agent that honours Secret on a send. An older one
// ignores it, so the write would land in the clear.
const MinSecretVersion = 2
