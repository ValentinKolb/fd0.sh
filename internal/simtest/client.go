package simtest

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// Client is one simulated fd0 user: an isolated FD0_HOME with its own
// vault, agent socket, and config pointing at all harness servers. It
// runs the real fd0 binary (which auto-spawns its agent) for every
// operation, so the exact production client code path is exercised.
type Client struct {
	Name    string
	h       *Harness
	home    string // FD0_HOME
	hostDir string // HOME (for agent + ssh sock isolation)
	sock    string // FD0_SSH_SOCK
	pass    string
	servers []string // this client's [sync].servers (defaults to all harness servers)
}

// AddClient creates a client configured with every harness server.
func (h *Harness) AddClient(name string) *Client {
	return h.AddClientWithServers(name, h.ServerURLs())
}

// AddClientWithServers creates a client with a specific [sync].servers
// list — used to exercise heterogeneous member configs (different order
// or subset), which primary-per-scope routing must agree across (RED #1).
func (h *Harness) AddClientWithServers(name string, servers []string) *Client {
	h.t.Helper()
	// Keep these paths SHORT: home holds the agent's unix socket, which
	// macOS caps at ~104 bytes (see harness.New).
	c := &Client{
		Name:    name,
		h:       h,
		home:    filepath.Join(h.dir, name),
		hostDir: filepath.Join(h.dir, name+"h"),
		sock:    filepath.Join(h.dir, name+".s"),
		pass:    name + "-pass",
		servers: servers,
	}
	mustMkdir(h.t, c.home)
	mustMkdir(h.t, c.hostDir)
	c.writeConfig()
	// init expects the passphrase twice (set + confirm); unlock once.
	if out, err := c.runStdin(c.pass+"\n"+c.pass+"\n", "init"); err != nil {
		h.t.Fatalf("%s init: %v\n%s", name, err, out)
	}
	if out, err := c.runStdin(c.pass+"\n", "unlock"); err != nil {
		h.t.Fatalf("%s unlock: %v\n%s", name, err, out)
	}
	h.Clients = append(h.Clients, c)
	return c
}

func (c *Client) writeConfig() {
	var b strings.Builder
	b.WriteString("[sync]\nservers = [")
	for i, u := range c.servers {
		if i > 0 {
			b.WriteString(", ")
		}
		fmt.Fprintf(&b, "%q", u)
	}
	b.WriteString("]\non_unlock = false\n")
	if c.h.PrimaryMode {
		b.WriteString("mode = \"primary\"\n")
	}
	mustWrite(c.h.t, filepath.Join(c.home, "config.toml"), b.String())
}

// SetServers rewrites this client's [sync].servers (and re-emits the
// config). Used to simulate a member whose configured set no longer
// contains a scope's primary (the missing-anchor case).
func (c *Client) SetServers(servers []string) {
	c.servers = servers
	c.writeConfig()
}

// ScopeIDs returns the scope ids this client has locally (its scope chain
// files are named s_<id>.cbor).
func (c *Client) ScopeIDs() []string {
	matches, _ := filepath.Glob(filepath.Join(c.home, "chains", "s_*.cbor"))
	out := make([]string, 0, len(matches))
	for _, m := range matches {
		out = append(out, strings.TrimSuffix(filepath.Base(m), ".cbor"))
	}
	return out
}

// env returns the process environment for this client's fd0 invocations.
func (c *Client) env() []string {
	return []string{
		"FD0_HOME=" + c.home,
		"HOME=" + c.hostDir,
		"FD0_SSH_SOCK=" + c.sock,
		"FD0_AGENT_BIN=" + c.h.agentBin,
		"FD0_AUTO_PIN=1",
		"PATH=" + pathEnv(),
	}
}

// run executes `fd0 <args...>` for this client and returns combined output.
func (c *Client) run(args ...string) (string, error) {
	return c.runStdin("", args...)
}

// runStdin is run with stdin supplied (for init/unlock passphrases).
func (c *Client) runStdin(stdin string, args ...string) (string, error) {
	c.h.mu.Lock()
	defer c.h.mu.Unlock()
	cmd := exec.Command(c.h.fd0Bin, args...)
	cmd.Env = c.env()
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	err := cmd.Run()
	return out.String(), err
}

// stopAgent kills this client's background agent. Reliable teardown is
// essential: a leaked agent per client per seed would accumulate and
// starve later agent spawns (observed as "agent: not ready"). We read
// the pid the agent wrote to <FD0_HOME>/agent.pid and signal it.
func (c *Client) stopAgent() {
	data, err := os.ReadFile(filepath.Join(c.home, "agent.pid"))
	if err != nil {
		return
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil || pid <= 0 {
		return
	}
	p, err := os.FindProcess(pid)
	if err != nil {
		return
	}
	_ = p.Signal(syscall.SIGTERM)
	// Escalate to SIGKILL if it doesn't exit promptly. The agent is not a
	// direct child (it was spawned by the fd0 CLI), so we can't Wait();
	// poll liveness with signal 0 and force-kill on timeout. A leaked
	// agent would starve later spawns ("agent: not ready").
	for i := 0; i < 25; i++ { // ~500ms
		if err := p.Signal(syscall.Signal(0)); err != nil {
			return // gone
		}
		time.Sleep(20 * time.Millisecond)
	}
	_ = p.Signal(syscall.SIGKILL)
}

// ── operations the schedule can issue ─────────────────────────────────

// Set writes key=val in scope (last-writer-wins on the name).
func (c *Client) Set(scope, key, val string) error {
	out, err := c.run("set", key, val, "--scope", scope)
	if err != nil {
		return fmt.Errorf("set %s=%s: %v\n%s", key, val, err, out)
	}
	return nil
}

// Get returns the current value of key in scope, or ("", false) if absent.
func (c *Client) Get(scope, key string) (string, bool) {
	out, err := c.run("get", key, "--scope", scope)
	if err != nil {
		return "", false
	}
	return strings.TrimRight(out, "\n"), true
}

// Sync runs `fd0 sync`. Returns the combined output and whether it exited 0.
// A non-nil error is NOT a test failure on its own — a degraded sync
// (some replica down) is expected and still exits 0; a hard failure is
// the interesting signal.
func (c *Client) Sync() (string, bool) {
	out, err := c.run("sync")
	return out, err == nil
}

// Doctor runs `fd0 doctor`; ok==true means a clean bill of health.
func (c *Client) Doctor() (string, bool) {
	out, err := c.run("doctor")
	return out, err == nil
}

// ── one-time scope sharing setup ──────────────────────────────────────

// ShareScope makes owner create a scope with the given label and admit
// every other client as a member, then syncs everyone so the membership
// is published and discovered. Returns the scope id (the label, since
// fd0 addresses scopes by label on the CLI). This mirrors the
// card-exchange + add-member flow a real team performs once.
func (h *Harness) ShareScope(owner *Client, label string, members ...*Client) {
	h.t.Helper()
	if out, err := owner.run("sync"); err != nil {
		h.t.Fatalf("%s pre-share sync: %v\n%s", owner.Name, err, out)
	}
	if out, err := owner.run("scope", "create", "--label", label); err != nil {
		h.t.Fatalf("scope create: %v\n%s", err, out)
	}
	for _, m := range members {
		// Ensure both ends are registered before card exchange.
		_, _ = m.run("sync")
		ownerCard := exportCard(h.t, owner)
		memberCard := exportCard(h.t, m)
		if out, err := owner.run("card", "import", memberCard, "--label", m.Name, "--yes"); err != nil {
			h.t.Fatalf("%s import %s card: %v\n%s", owner.Name, m.Name, err, out)
		}
		if out, err := m.run("card", "import", ownerCard, "--label", owner.Name, "--yes"); err != nil {
			h.t.Fatalf("%s import %s card: %v\n%s", m.Name, owner.Name, err, out)
		}
		if out, err := owner.run("scope", "add-member", m.Name, "--scope", label); err != nil {
			h.t.Fatalf("add-member %s: %v\n%s", m.Name, err, out)
		}
	}
	if out, err := owner.run("sync"); err != nil {
		h.t.Fatalf("%s publish-membership sync: %v\n%s", owner.Name, err, out)
	}
	for _, m := range members {
		if out, err := m.run("sync"); err != nil {
			h.t.Fatalf("%s discover-scope sync: %v\n%s", m.Name, err, out)
		}
	}
}

func exportCard(t *testing.T, c *Client) string {
	t.Helper()
	out, err := c.run("card", "export")
	if err != nil {
		t.Fatalf("%s card export: %v\n%s", c.Name, err, out)
	}
	for _, line := range strings.Split(out, "\n") {
		if strings.HasPrefix(line, "fd0://card/") {
			return strings.TrimSpace(line)
		}
	}
	t.Fatalf("%s card export: no fd0://card/ line in:\n%s", c.Name, out)
	return ""
}
