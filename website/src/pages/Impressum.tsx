/**
 * /impressum — § 5 DDG legal page for fd0.sh.
 *
 * Same legal substance as the geomark imprint, adapted for fd0:
 *   - Apache-2.0 (not MIT)
 *   - no third-party data sources (geomark cited GeoNames + OpenAddresses)
 *   - no localStorage / interactive API surface (the homepage is fully
 *     server-rendered with no client-side state)
 *
 * Visual register matches the homepage: phosphor amber on near-black,
 * Geist Mono, framed sections with uppercase dim labels — the same
 * man-page pattern used for NAME / DESCRIPTION / COMPONENTS on /.
 *
 * Email is rendered as HTML character entities so basic regex scrapers
 * miss the typical pattern. Browsers decode entities at parse time, so
 * users see and click a normal `mailto:` link.
 */

import { ssr } from "../../config";

// ─── shared section label (mirrors the homepage's NAME/DESCRIPTION style) ──

const Block = (p: { label: string; aside?: string; children: any }) => (
  <section class="mt-8 frame">
    <div class="flex flex-wrap items-baseline justify-between gap-x-6 gap-y-1">
      <div class="text-xs dim tracking-widest uppercase">{p.label}</div>
      {p.aside ? <div class="text-xs dim">{p.aside}</div> : null}
    </div>
    <div class="mt-4 text-[14px] leading-relaxed">{p.children}</div>
  </section>
);

const H = (p: { children: any }) => (
  <div class="acc text-sm mt-5 first:mt-0 mb-1.5 font-medium">{p.children}</div>
);

// ─── email obfuscation ─────────────────────────────────────────────────

const encodeEntities = (s: string): string =>
  s
    .split("")
    .map((c) => `&#${c.charCodeAt(0)};`)
    .join("");

const EMAIL_PLAIN = "mail@valentin-kolb.com";
const EMAIL_ENC = encodeEntities(EMAIL_PLAIN);
const MAILTO_ENC = encodeEntities(`mailto:${EMAIL_PLAIN}`);

// ─── page ──────────────────────────────────────────────────────────────

const Impressum = () => (
  <div class="term px-6 md:px-12 py-10">
    <div class="max-w-3xl mx-auto">
      <header>
        <div class="dim text-xs tracking-widest uppercase">
          /usr/share/man/man7/fd0-impressum.7
        </div>
        <h1 class="acc text-3xl md:text-4xl mt-3 font-medium">
          Impressum{" "}
          <span class="dim font-normal">
            — Anbieterkennzeichnung nach § 5 DDG
          </span>
        </h1>
        <p class="dim text-sm mt-4 max-w-2xl leading-relaxed">
          Pflichtangaben für die unter{" "}
          <span class="acc">fd0.sh</span> betriebene Website und das auf{" "}
          <span class="acc">github.com/ValentinKolb/fd0.sh</span>{" "}
          veröffentlichte Open-Source-Projekt.
        </p>
      </header>

      <Block label="Anbieter" aside="§ 5 DDG">
        <address class="not-italic">
          Valentin Kolb
          <br />
          Maienweg 22
          <br />
          89081 Ulm
          <br />
          Deutschland
        </address>
      </Block>

      <Block label="Kontakt" aside="email only">
        <p class="dim">
          E-Mail:{" "}
          <a
            href={MAILTO_ENC}
            class="acc"
            innerHTML={EMAIL_ENC}
          />
        </p>
      </Block>

      <Block label="Inhaltliche Verantwortung" aside="§ 18 Abs. 2 MStV">
        <p class="dim">
          Verantwortlich für den Inhalt: Valentin Kolb (Anschrift wie oben).
        </p>
      </Block>

      <Block label="Haftungsausschluss" aside="content + links + ©">
        <H>Haftung für Inhalte</H>
        <p class="dim">
          Die Inhalte dieser Website wurden mit größter Sorgfalt erstellt.
          Für die Richtigkeit, Vollständigkeit und Aktualität der Inhalte
          kann jedoch keine Gewähr übernommen werden. Als Diensteanbieter
          bin ich gemäß § 7 Abs. 1 DDG für eigene Inhalte auf diesen Seiten
          nach den allgemeinen Gesetzen verantwortlich. Nach §§ 8 bis 10
          DDG bin ich als Diensteanbieter jedoch nicht verpflichtet,
          übermittelte oder gespeicherte fremde Informationen zu
          überwachen oder nach Umständen zu forschen, die auf eine
          rechtswidrige Tätigkeit hinweisen.
        </p>

        <H>Haftung für Links</H>
        <p class="dim">
          Diese Website enthält Links zu externen Websites Dritter, auf
          deren Inhalte ich keinen Einfluss habe. Deshalb kann ich für
          diese fremden Inhalte auch keine Gewähr übernehmen. Für die
          Inhalte der verlinkten Seiten ist stets der jeweilige Anbieter
          oder Betreiber der Seiten verantwortlich. Bei Bekanntwerden von
          Rechtsverletzungen werden derartige Links umgehend entfernt.
        </p>

        <H>Urheberrecht</H>
        <p class="dim">
          Der Quellcode dieser Website sowie der Code der Komponenten{" "}
          <span class="acc">fd0</span>, <span class="acc">fd0-agent</span>,{" "}
          <span class="acc">fd0-server</span> und{" "}
          <span class="acc">fd0-witness</span> stehen unter der
          Apache-2.0-Lizenz (siehe{" "}
          <a href="https://github.com/ValentinKolb/fd0.sh/blob/main/LICENSE" class="acc">
            LICENSE
          </a>
          ). Die in den Codebeispielen verwendeten Befehls- und
          Protokollnamen sind Teil der dort veröffentlichten Spezifikationen
          und stehen unter derselben Lizenz.
        </p>
      </Block>

      <Block label="Datenschutz" aside="no tracking · no cookies">
        <p class="dim">
          Diese Website setzt keine Cookies, lädt keine Drittanbieter-Tracker
          und nutzt keine Analyse-Werkzeuge wie Google Analytics, Plausible
          o. ä. Es werden keine personenbezogenen Daten erhoben oder
          verarbeitet, die über das technisch Notwendige hinausgehen.
        </p>

        <H>Kein Client-State</H>
        <p class="dim">
          Die Seite wird vollständig serverseitig gerendert und kommt ohne
          clientseitiges JavaScript-State-Management aus. Es werden keine
          Daten im <span class="acc">localStorage</span>,{" "}
          <span class="acc">sessionStorage</span> oder in{" "}
          <span class="acc">IndexedDB</span> des Browsers abgelegt.
        </p>

        <H>Server-Logs</H>
        <p class="dim">
          Der Webserver kann technische Zugriffsdaten (Zeitstempel,
          IP-Adresse, User-Agent, angefragte URL, Statuscode) vorübergehend
          zur Fehlerbehebung und Abwehr von Missbrauch verarbeiten. Eine
          darüber hinausgehende Auswertung oder Weitergabe findet nicht
          statt.
        </p>

        <H>Rechtsgrundlage</H>
        <p class="dim">
          Rechtsgrundlage für die o. g. Verarbeitungen ist Art. 6 Abs. 1
          lit. f DSGVO (berechtigtes Interesse am Betrieb einer technisch
          funktionierenden Website).
        </p>

        <H>Selbstgehostete Instanzen</H>
        <p class="dim">
          Dieses Impressum bezieht sich ausschließlich auf die unter{" "}
          <span class="acc">fd0.sh</span> betriebene Website. Wer die
          Open-Source-Komponenten <span class="acc">fd0-server</span> oder{" "}
          <span class="acc">fd0-witness</span> auf eigener Infrastruktur
          betreibt, ist für die dort verarbeiteten Daten und etwaige
          datenschutzrechtliche Pflichten selbst verantwortlich.
        </p>
      </Block>

      <footer class="mt-16 mb-4 border-t rule pt-6">
        <div class="text-xs dim">SEE ALSO</div>
        <div class="mt-2 flex flex-wrap gap-x-6 gap-y-1 text-sm">
          <a href="/">fd0(1)</a>
          <a href="https://github.com/ValentinKolb/fd0.sh/blob/main/LICENSE">
            LICENSE
          </a>
          <a href="https://github.com/ValentinKolb/fd0.sh">
            github.com/ValentinKolb/fd0.sh
          </a>
        </div>
        <div class="mt-6 dim text-xs flex justify-between items-baseline">
          <span>fd0.sh — Apache-2.0</span>
          <a href="/">../</a>
        </div>
      </footer>
    </div>
  </div>
);

export default ssr(async (c) => {
  const page = c.get("page");
  page.title = "fd0 — Impressum";
  page.description =
    "Anbieterkennzeichnung nach § 5 DDG für fd0.sh.";
  return () => <Impressum />;
});
