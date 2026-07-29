export type InputMetadata = {
  type: string;
  autocomplete: string;
  name: string;
  id: string;
};

export type LoginFields = {
  username?: HTMLInputElement;
  password: HTMLInputElement;
};

export function usernameScore(field: InputMetadata): number {
  const autocomplete = field.autocomplete.toLowerCase();
  if (autocomplete === "username") return 120;
  if (autocomplete === "email") return 110;

  const identity = `${field.name} ${field.id}`.toLowerCase();
  if (/\b(user(name)?|login|email)\b/.test(identity)) return 90;
  if (field.type === "email") return 80;
  if (field.type === "text") return 20;
  return 0;
}

export function passwordScore(field: InputMetadata): number {
  if (field.type !== "password") return 0;
  const autocomplete = field.autocomplete.toLowerCase();
  if (autocomplete === "new-password") return -1;
  if (autocomplete === "current-password") return 120;
  return 60;
}

export function findLoginFields(document: Document): LoginFields | undefined {
  const inputs = [...document.querySelectorAll<HTMLInputElement>("input")].filter(
    isFillable,
  );
  const password = bestInput(inputs, passwordScore);
  if (!password) return undefined;

  const beforePassword = inputs.filter(
    (input) =>
      input !== password &&
      Boolean(input.compareDocumentPosition(password) & Node.DOCUMENT_POSITION_FOLLOWING),
  );
  const username = bestInput(
    beforePassword.length > 0 ? beforePassword : inputs.filter((input) => input !== password),
    usernameScore,
  );
  return { username, password };
}

export function fillLogin(
  document: Document,
  credential: { username?: string; password: string },
): { usernameFilled: boolean; passwordFilled: boolean } {
  const fields = findLoginFields(document);
  if (!fields) return { usernameFilled: false, passwordFilled: false };

  let usernameFilled = false;
  if (fields.username && credential.username) {
    setInputValue(fields.username, credential.username);
    usernameFilled = true;
  }
  setInputValue(fields.password, credential.password);
  return { usernameFilled, passwordFilled: true };
}

function bestInput(
  inputs: HTMLInputElement[],
  score: (metadata: InputMetadata) => number,
): HTMLInputElement | undefined {
  let best: { input: HTMLInputElement; score: number } | undefined;
  for (const input of inputs) {
    const current = score({
      type: input.type.toLowerCase(),
      autocomplete: input.autocomplete,
      name: input.name,
      id: input.id,
    });
    if (current > 0 && (!best || current > best.score)) {
      best = { input, score: current };
    }
  }
  return best?.input;
}

function isFillable(input: HTMLInputElement): boolean {
  if (input.disabled || input.readOnly || input.type === "hidden") return false;
  const style = getComputedStyle(input);
  if (style.display === "none" || style.visibility === "hidden" || Number(style.opacity) === 0) {
    return false;
  }
  const rect = input.getBoundingClientRect();
  return rect.width > 0 && rect.height > 0;
}

function setInputValue(input: HTMLInputElement, value: string): void {
  const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value")?.set;
  if (!setter) throw new Error("Browser does not expose the input value setter.");
  setter.call(input, value);
  input.dispatchEvent(new Event("input", { bubbles: true, composed: true }));
  input.dispatchEvent(new Event("change", { bubbles: true, composed: true }));
}
