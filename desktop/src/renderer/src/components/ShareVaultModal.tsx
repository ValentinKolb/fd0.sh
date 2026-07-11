import { For, Show, createMemo, createSignal, onMount, type JSX } from "solid-js";
import {
  IconArrowLeft,
  IconCopy,
  IconShieldCheck,
  IconUserMinus,
  IconUserPlus,
  IconUsers,
  IconX,
} from "@tabler/icons-solidjs";
import type { IdentityCardInfo, ScopeShareInfo, ScopeSummary, TrustedContact } from "../../../shared/contracts";
import { errorText } from "../errors";
import { IconButton } from "./Controls";

export function ShareVaultModal(props: {
  scope: ScopeSummary;
  onClose(): void;
  onChanged(): Promise<void>;
  onNotify(message: string): void;
}): JSX.Element {
  const [mode, setMode] = createSignal<"access" | "new-contact">("access");
  const [info, setInfo] = createSignal<ScopeShareInfo>({ contacts: [], members: [] });
  const [ownCard, setOwnCard] = createSignal<IdentityCardInfo | null>(null);
  const [cardURL, setCardURL] = createSignal("");
  const [contactLabel, setContactLabel] = createSignal("");
  const [cardPreview, setCardPreview] = createSignal<IdentityCardInfo | null>(null);
  const [reviewedURL, setReviewedURL] = createSignal("");
  const [loading, setLoading] = createSignal(true);
  const [busy, setBusy] = createSignal("");
  const [error, setError] = createSignal("");
  const available = createMemo(() => info().contacts.filter((contact) => !contact.shared));
  const canTrust = createMemo(() => Boolean(cardPreview() && reviewedURL() === cardURL().trim() && contactLabel().trim()));

  async function loadInfo(showLoading = true): Promise<void> {
    if (showLoading) setLoading(true);
    try {
      setInfo(await window.fd0.scopeShareInfo(props.scope.id));
    } catch (cause) {
      setError(errorText(cause));
    } finally {
      if (showLoading) setLoading(false);
    }
  }

  onMount(() => void loadInfo());

  async function finishMembershipChange(message: string): Promise<void> {
    let syncError = "";
    if (!window.fd0.development) {
      try {
        await window.fd0.sync();
      } catch (cause) {
        syncError = `The access change is saved locally, but sync failed. ${errorText(cause)}`;
      }
    }
    await loadInfo(false);
    await props.onChanged();
    props.onNotify(message);
    if (syncError) {
      setError(syncError);
    }
  }

  async function shareContact(contact: TrustedContact): Promise<void> {
    setBusy(`add:${contact.label}`);
    setError("");
    try {
      await window.fd0.addScopeMember(props.scope.id, contact.label);
      await finishMembershipChange(`Shared ${props.scope.label} with ${contact.label}.`);
    } catch (cause) {
      setError(errorText(cause));
    } finally {
      setBusy("");
    }
  }

  async function removeMember(memberID: string, label: string): Promise<void> {
    setBusy(`remove:${memberID}`);
    setError("");
    try {
      const result = await window.fd0.removeScopeMember(props.scope.id, memberID, label);
      if (!result.ok) return;
      await finishMembershipChange(`Removed ${label} from ${props.scope.label}.`);
    } catch (cause) {
      setError(errorText(cause));
    } finally {
      setBusy("");
    }
  }

  async function copyOwnCard(): Promise<void> {
    setBusy("own-card");
    setError("");
    try {
      const card = ownCard() ?? await window.fd0.exportIdentityCard();
      setOwnCard(card);
      if (!card.url) throw new Error("Identity card export did not return a URL.");
      await window.fd0.copyText(card.url);
      props.onNotify(`Identity card copied. It expires ${formatCardExpiry(card.expiresAt)}.`);
    } catch (cause) {
      setError(errorText(cause));
    } finally {
      setBusy("");
    }
  }

  async function reviewCard(): Promise<void> {
    const url = cardURL().trim();
    if (!url) return;
    setBusy("review-card");
    setError("");
    try {
      const preview = await window.fd0.inspectIdentityCard(url);
      setCardPreview(preview);
      setReviewedURL(url);
      if (!contactLabel().trim()) setContactLabel(preview.shortId);
    } catch (cause) {
      setCardPreview(null);
      setReviewedURL("");
      setError(errorText(cause));
    } finally {
      setBusy("");
    }
  }

  async function trustAndShare(event: SubmitEvent): Promise<void> {
    event.preventDefault();
    const label = contactLabel().trim();
    const url = cardURL().trim();
    if (!canTrust()) return;
    setBusy("import-card");
    setError("");
    try {
      const imported = await window.fd0.importIdentityCard(url, label);
      if (!imported.ok) return;
      await window.fd0.addScopeMember(props.scope.id, label);
      await finishMembershipChange(`Trusted ${label} and shared ${props.scope.label}.`);
      setMode("access");
      setCardURL("");
      setContactLabel("");
      setCardPreview(null);
      setReviewedURL("");
    } catch (cause) {
      setError(errorText(cause));
    } finally {
      setBusy("");
    }
  }

  return (
    <div class="modal-backdrop" role="presentation" onPointerDown={(event) => event.target === event.currentTarget && props.onClose()}>
      <section class="modal share-modal" role="dialog" aria-modal="true" aria-labelledby="share-vault-title">
        <header>
          <div class="share-title">
            <Show when={mode() === "new-contact"}>
              <IconButton label="Back to vault access" onClick={() => { setMode("access"); setError(""); }}><IconArrowLeft size={18} /></IconButton>
            </Show>
            <div>
              <h1 id="share-vault-title">{mode() === "access" ? `Access to ${props.scope.label}` : "Add a new contact"}</h1>
              <p>{mode() === "access" ? "Everyone listed can decrypt every current and future item in this vault." : "Exchange signed identity cards and verify the safety number out of band."}</p>
            </div>
          </div>
          <IconButton label="Close" onClick={props.onClose}><IconX size={18} /></IconButton>
        </header>

        <Show
          when={mode() === "access"}
          fallback={
            <form class="share-add-contact" onSubmit={trustAndShare}>
              <section class="share-section card-exchange-row">
                <div><h2>Send your card</h2><p>The other person imports this URL in fd0. Cards expire after 24 hours.</p></div>
                <button class="secondary-button" type="button" disabled={busy() === "own-card"} onClick={() => void copyOwnCard()}><IconCopy size={16} />{busy() === "own-card" ? "Preparing…" : "Copy my card"}</button>
              </section>
              <section class="share-section new-contact-fields">
                <div><h2>Add their card</h2><p>Paste the URL they exported, then compare the safety number through a trusted channel.</p></div>
                <label><span>Identity card URL</span><textarea required spellcheck={false} placeholder="fd0://card/…" value={cardURL()} onInput={(event) => { setCardURL(event.currentTarget.value); setCardPreview(null); setReviewedURL(""); }} /></label>
                <label><span>Contact name</span><input required maxlength="80" placeholder="Benny" value={contactLabel()} onInput={(event) => setContactLabel(event.currentTarget.value)} /></label>
                <button class="secondary-button review-card-button" type="button" disabled={!cardURL().trim() || busy() === "review-card"} onClick={() => void reviewCard()}><IconShieldCheck size={16} />{busy() === "review-card" ? "Checking…" : "Review card"}</button>
                <Show when={cardPreview()}>
                  {(preview) => (
                    <div class="card-preview" role="status">
                      <div><span>Safety number</span><strong>{preview().shortId} · {preview().fingerprint}…</strong></div>
                      <code>{preview().safetyNumber}</code>
                      <small>Expires {formatCardExpiry(preview().expiresAt)}. Compare every group before continuing.</small>
                    </div>
                  )}
                </Show>
              </section>
              <Show when={error()}><div class="inline-error" role="alert">{error()}</div></Show>
              <footer>
                <button class="secondary-button" type="button" onClick={() => { setMode("access"); setError(""); }}>Cancel</button>
                <button class="primary-button" type="submit" disabled={!canTrust() || busy() === "import-card"}>{busy() === "import-card" ? "Sharing…" : "Trust and share…"}</button>
              </footer>
            </form>
          }
        >
          <div class="share-access-content">
            <Show when={!loading()} fallback={<div class="share-loading">Loading vault access…</div>}>
              <section class="share-section">
                <div class="share-section-heading"><div><h2>People with access</h2><p>{info().members.length} {info().members.length === 1 ? "member" : "members"}</p></div></div>
                <div class="access-list">
                  <For each={info().members}>
                    {(member) => (
                      <div class="access-row">
                        <span class="access-avatar"><IconUsers size={17} /></span>
                        <span class="access-person"><strong>{member.label}</strong><small>{member.fingerprint}…{member.self ? " · this device" : member.trusted ? " · trusted contact" : " · not in contacts"}</small></span>
                        <Show when={!member.self}>
                          <button class="access-remove" type="button" disabled={busy() === `remove:${member.id}`} onClick={() => void removeMember(member.id, member.label)}><IconUserMinus size={16} />Remove</button>
                        </Show>
                      </div>
                    )}
                  </For>
                </div>
              </section>
              <section class="share-section">
                <div class="share-section-heading"><div><h2>Trusted contacts</h2><p>Add someone whose identity card you already verified.</p></div><button class="secondary-button" type="button" onClick={() => { setMode("new-contact"); setError(""); }}><IconUserPlus size={16} />New contact</button></div>
                <Show
                  when={available().length > 0}
                  fallback={<div class="share-empty compact"><IconUsers size={20} /><div><strong>No available contacts</strong><span>Everyone you trust already has access, or you have not added another identity card yet.</span></div></div>}
                >
                  <div class="access-list trusted-contact-list">
                    <For each={available()}>
                      {(contact) => (
                        <div class="access-row">
                          <span class="access-avatar trusted"><IconShieldCheck size={17} /></span>
                          <span class="access-person"><strong>{contact.label}</strong><small>{contact.fingerprint}…</small></span>
                          <button class="access-add" type="button" disabled={busy() === `add:${contact.label}`} onClick={() => void shareContact(contact)}><IconUserPlus size={16} />Add</button>
                        </div>
                      )}
                    </For>
                  </div>
                </Show>
              </section>
              <Show when={error()}><div class="inline-error share-error" role="alert">{error()}</div></Show>
            </Show>
          </div>
          <footer class="share-footer">
            <button class="secondary-button" type="button" disabled={busy() === "own-card"} onClick={() => void copyOwnCard()}><IconCopy size={16} />{busy() === "own-card" ? "Preparing…" : "Copy my card"}</button>
            <button class="primary-button" type="button" onClick={props.onClose}>Done</button>
          </footer>
        </Show>
      </section>
    </div>
  );
}

function formatCardExpiry(raw: string): string {
  const date = new Date(raw);
  if (Number.isNaN(date.valueOf())) return "soon";
  return new Intl.DateTimeFormat(undefined, { dateStyle: "medium", timeStyle: "short" }).format(date);
}
