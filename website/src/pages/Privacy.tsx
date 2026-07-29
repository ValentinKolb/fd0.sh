import { setPageSeo, ssr } from "../../config";
import { C, FONT_MONO, FONT_SANS, Footer, Nav } from "../lib/chrome";

const Section = (p: { title: string; children: any }) => (
  <section class="mb-12">
    <h2 class="text-xl md:text-2xl font-medium mb-4">{p.title}</h2>
    <div
      class="space-y-4 text-[15px] leading-relaxed"
      style={`color:${C.dim};`}
    >
      {p.children}
    </div>
  </section>
);

const List = (p: { children: any }) => (
  <ul class="list-disc pl-5 space-y-2">{p.children}</ul>
);

const Code = (p: { children: any }) => (
  <code style={`font-family:${FONT_MONO};color:${C.acc};`}>
    {p.children}
  </code>
);

const PrivacyPage = () => (
  <div
    class="min-h-screen"
    style={`background:${C.bg};color:${C.fg};font-family:${FONT_SANS};`}
  >
    <Nav />
    <main class="max-w-3xl mx-auto px-6 md:px-10 py-16 md:py-24">
      <div
        class="text-[11px] tracking-[0.18em] uppercase mb-4 font-medium"
        style={`color:${C.acc};`}
      >
        Privacy
      </div>
      <h1 class="text-4xl md:text-5xl font-medium tracking-tight mb-5">
        How fd0 handles your data.
      </h1>
      <p
        class="text-lg leading-relaxed mb-14 max-w-2xl"
        style={`color:${C.dim};`}
      >
        This policy covers fd0 Desktop, the fd0 CLI and local agent, the fd0
        browser extension, the official hosted sync service, and the fd0.sh
        website. fd0 is local-first: secret contents are encrypted on your
        device before they can be synced.
      </p>

      <Section title="The short version">
        <List>
          <li>
            fd0 Desktop, the CLI, and the agent do not send usage analytics or
            advertising identifiers.
          </li>
          <li>
            The hosted sync service receives ciphertext, signed events, and
            the protocol metadata needed to sync them. It cannot read secret
            values, secret names, passphrases, private keys, or scope keys.
          </li>
          <li>
            The fd0 browser extension processes the active HTTPS origin and
            supported login fields locally. Passwords and one-time passwords
            are requested only after an explicit user action.
          </li>
          <li>
            The fd0.sh website uses no advertising, tracking analytics, or
            tracking cookies.
          </li>
        </List>
      </Section>

      <Section title="Desktop app, CLI, and local agent">
        <p>
          fd0 stores an encrypted vault, signed local event chains, non-secret
          configuration, and optional user-created recovery exports on the
          device. The local agent keeps the unlocked cryptographic identity and
          SSH key material in memory so the Desktop app and CLI can use one
          unlocked session.
        </p>
        <p>
          Desktop settings and redacted diagnostic events are stored locally.
          Diagnostic data is not uploaded automatically; it leaves the device
          only when the user explicitly copies or shares it. The packaged
          Desktop app periodically checks for signed releases. Installing or
          updating can connect to fd0.sh and GitHub and exposes ordinary
          network request metadata to those services.
        </p>
        <p>
          When a user starts SSH, SFTP, Kubernetes, Talos, or another remote
          operation, fd0 connects to the destination chosen by the user. That
          destination and its operator receive the data inherent to that
          connection.
        </p>
      </Section>

      <Section title="fd0 browser extension">
        <p>
          The fd0 browser extension connects Chrome to the encrypted fd0 vault
          through a narrow native messaging host on the same device. It
          handles:
        </p>
        <List>
          <li>
            the active HTTPS origin, used to find matching logins and prevent
            credentials from being returned to another origin;
          </li>
          <li>
            visible login form fields needed for autofill or an explicit
            save/update action;
          </li>
          <li>
            login titles, usernames, vault labels, opaque credential IDs, and
            revisions returned by the local host for that origin; and
          </li>
          <li>
            a password or one-time password only after an explicit user
            action. TOTP seeds remain in the encrypted fd0 vault.
          </li>
        </List>
        <p>
          The extension does not store passwords, TOTP seeds, or one-time
          passwords in Chrome Local Storage or Chrome Sync. A login candidate
          detected after form submission may be held in Chrome session storage
          for at most 60 seconds so the user can choose to save or update it.
          It is scoped to the originating tab, frame, and HTTPS origin and is
          then deleted.
        </p>
        <p>
          <Code>https://*/*</Code> lets the extension detect supported login
          fields on encrypted pages. <Code>nativeMessaging</Code> connects it
          to the local fd0 host. <Code>activeTab</Code> and{" "}
          <Code>scripting</Code> support explicit toolbar actions and reconnect
          eligible pages after an extension update. <Code>storage</Code> and{" "}
          <Code>alarms</Code> hold and expire the short-lived candidate
          described above.
        </p>
        <p>
          The extension does not remotely collect this browser data. Its use
          and transfer of information received from Chrome APIs adheres to the
          Chrome Web Store User Data Policy, including the Limited Use
          requirements.
        </p>
      </Section>

      <Section title="Official hosted sync service">
        <p>
          The official primary service at <Code>api.fd0.sh</Code> stores
          encrypted, signed protocol events. <Code>api2.fd0.sh</Code> is its
          read-only disaster-recovery replica, not a second writable sync
          target. It receives the same encrypted event history for recovery
          purposes.
        </p>
        <p>
          Necessary metadata remains visible to both systems: public identity
          keys, a random short user ID, chain and scope identifiers, membership
          changes, signatures, event order and time, ciphertext sizes, and sync
          or replication request timing.
        </p>
        <p>
          TLS is terminated by the service infrastructure. Source IP addresses
          are used for in-memory abuse and rate-limit controls and may appear in
          operational proxy or security logs. Idle in-process rate-limit
          entries are normally removed after ten minutes. Accepted protocol
          events are append-only and retained indefinitely so clients can
          verify history and detect rollback or equivocation. Encrypted events
          are also included in operational and disaster-recovery backups.
        </p>
        <p>
          A self-hosted fd0 server follows the same ciphertext-only protocol,
          but its operator chooses the infrastructure, logging, and retention
          practices and is responsible for its own privacy information.
        </p>
      </Section>

      <Section title="fd0.sh website">
        <p>
          The website does not use accounts, advertising, behavioral
          analytics, third-party tracking pixels, or tracking cookies. It
          records aggregate request counts and operational logs such as the
          requested path, response status, and timing. The hosting layer
          necessarily receives normal connection data such as source IP
          addresses.
        </p>
        <p>
          Following a link to GitHub or downloading a release hosted by GitHub
          transfers the request to GitHub, where GitHub&apos;s privacy terms
          apply.
        </p>
      </Section>

      <Section title="Sharing, security, and retention">
        <p>
          fd0 does not sell personal data, use it for advertising or credit
          decisions, or make credential contents available to the service
          operator. Data is used only to provide, secure, maintain, and support
          the fd0 features described here.
        </p>
        <p>
          Official fd0.sh infrastructure is operated in Germany by Kolb Antik
          GmbH, with a disaster-recovery service and ciphertext off-site
          backups hosted at Hetzner in Germany. Infrastructure providers process
          ordinary network and encrypted service data only as needed to operate
          that infrastructure.
        </p>
        <p>
          Local vault data remains until the user changes or deletes it or
          removes the local fd0 data. Browser session candidates expire as
          described above. Hosted sync history follows the append-only
          retention described above.
        </p>
      </Section>

      <Section title="Your control and rights">
        <p>
          Users can lock fd0, edit or logically delete records, change or
          disable sync, choose a self-hosted server, remove the browser
          extension, and unregister its native host with{" "}
          <Code>fd0 browser disable</Code>. Removing an app or extension does
          not by itself delete the fd0 vault.
        </p>
        <p>
          For personal data handled by the official service, applicable rights
          may include access, correction, deletion, restriction, portability,
          objection, and a complaint to a data-protection authority. fd0 cannot
          identify or decrypt local-only data, and the hosted service cannot
          decrypt synced records. Append-only integrity records cannot be
          silently rewritten; record deletion is represented by a new signed
          event from the user&apos;s device.
        </p>
      </Section>

      <Section title="Operator, contact, and changes">
        <p>
          The official fd0.sh services and the fd0 browser extension are
          operated by Kolb Antik GmbH, Germany. Full legal contact details are
          available in the{" "}
          <a href="/impressum" style={`color:${C.acc};`}>
            Impressum
          </a>
          . Privacy questions or requests can be sent to{" "}
          <a href="mailto:mail@valentin-kolb.com" style={`color:${C.acc};`}>
            mail@valentin-kolb.com
          </a>
          .
        </p>
        <p>
          Material changes to how fd0 handles data will be reflected here. A
          change affecting the browser extension will also be reflected in its
          Chrome Web Store disclosure before release.
        </p>
        <p>Effective date: 29 July 2026.</p>
      </Section>
    </main>
    <Footer />
  </div>
);

export default ssr(async (c) => {
  setPageSeo(c, "privacy");
  return () => <PrivacyPage />;
});
