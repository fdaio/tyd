package main

import (
	"fmt"
	"os"
	"strings"
	"text/tabwriter"
	"time"
	"tyd/internal/controlpanel"

	"tyd/internal/alias"
	"tyd/internal/client"
	"tyd/internal/cpclient"
	"tyd/internal/peers"
	"tyd/internal/recent"
	"tyd/internal/transport"
)

func formatStatusConnErr(ep client.Endpoint, err error) string {
	if err == nil {
		return "daemon unreachable"
	}
	unix := ep.Kind == transport.KindUnix || ep.Kind == ""
	msg := strings.ToLower(err.Error())
	if unix && (strings.Contains(msg, "connection refused") ||
		strings.Contains(msg, "no such file") ||
		strings.Contains(msg, "not exist") ||
		strings.Contains(msg, "invalid argument")) {
		return "local daemon not running; start with tyd up"
	}
	return "daemon unreachable: " + err.Error()
}

func runStatus(opts options) error {
	doc, err := peers.Load(opts.peers)
	if err != nil {
		return err
	}
	// Archiving runs on the read paths so that a host which only ever runs
	// `status` still honours its TTL. It hides nothing here: status is where an
	// operator checks what is paired, and an archived peer is still paired.
	pruneArchive(opts)
	platform, _ := platformFor(opts)
	fmt.Println("Control Panel")
	fmt.Printf("  platform:   %s\n", platform)
	fmt.Printf("  relay:      %s\n", relayURL(opts))
	if doc.HasRegistration() {
		reg := doc.Registration
		url := reg.URL
		if url == "" {
			url = platform + "/" + reg.ID
		}
		fmt.Printf("  registered: %s\n", url)
		fmt.Printf("  id:         %s\n", reg.ID)
		fmt.Printf("  approval:   %s\n", reg.ApprovalMode)
		if reg.ApprovalMode == controlpanel.ApprovalFull {
			fmt.Println("              (full: remote peers attach and watch without being asked)")
		}
		epAddr, epFP, epErr := cpclient.New(platform).GetEndpoint(reg.ID)
		if epErr != nil {
			fmt.Printf("  endpoint:   (none / expired)\n")
		} else {
			fmt.Printf("  endpoint:   %s  fp=%s\n", epAddr, shortFP(epFP))
		}
	} else {
		fmt.Println("  registered: (no)")
	}
	fmt.Println()
	fmt.Println("Peers")
	if len(doc.Peers) == 0 {
		fmt.Println("  (none)")
	} else {
		tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
		fmt.Fprintln(tw, "ID\tNICK\tDIRECTION\tPAIRED")
		for _, p := range doc.Peers {
			nick := p.Nickname
			if nick == "" {
				nick = "-"
			}
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", p.ID, nick, p.Direction, p.PairedAt.Format(time.RFC3339))
		}
		_ = tw.Flush()
	}
	if rec, _ := recent.Load(opts.recent); rec != nil && (rec.PeerID != "" || rec.SessionID != "") {
		fmt.Println()
		fmt.Println("Recent")
		if rec.PeerID != "" {
			fmt.Printf("  peer:    %s\n", rec.PeerID)
		}
		if rec.SessionID != "" {
			fmt.Printf("  session: %s\n", rec.SessionID)
		}
	}
	if adoc, _ := alias.Load(opts.aliases); adoc != nil && len(adoc.Aliases) > 0 {
		fmt.Println()
		fmt.Println("Session aliases")
		tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
		fmt.Fprintln(tw, "ALIAS\tSESSION\tPEER")
		for _, e := range adoc.Aliases {
			fmt.Fprintf(tw, "%s\t%s\t%s\n", e.Name, e.SessionID, e.PeerID)
		}
		_ = tw.Flush()
	}

	fmt.Println()
	fmt.Println("Connections")
	key, err := loadIdentity(opts.identity)
	if err != nil {
		return err
	}
	ep, _, err := endpoint(opts)
	if err != nil {
		return err
	}
	items, err := client.Status(ep, key)
	if err != nil {
		fmt.Printf("  (%s)\n", formatStatusConnErr(ep, err))
		return nil
	}
	if len(items) == 0 {
		fmt.Println("  (none)")
		return nil
	}
	tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "ID\tTRANSPORT\tREMOTE\tTLS\tSTATE\tPRINCIPAL\tSESSION\tSINCE")
	for _, it := range items {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%v\t%s\t%s\t%s\t%s\n",
			it.ID, it.Transport, it.RemoteAddr, it.TLS, it.State, it.Principal, it.SessionID, it.EstablishedAt)
	}
	return tw.Flush()
}

func shortFP(fp string) string {
	if len(fp) > 16 {
		return fp[:16]
	}
	return fp
}

func shortPeer(id string) string {
	if len(id) > 8 {
		return id[:8]
	}
	return id
}
