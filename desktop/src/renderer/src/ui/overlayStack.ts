/**
 * A single ordering for everything that Escape can dismiss.
 *
 * Modals and popovers both listen for Escape on `document` in the capture
 * phase. Listener order there is registration order, not visual order, so a
 * modal mounted before a popover would swallow the key and close itself while
 * the popover on top stayed open. Every dismissible surface registers here
 * instead and only the topmost one acts.
 */
const stack: symbol[] = [];

export function pushOverlay(): symbol {
  const token = Symbol("overlay");
  stack.push(token);
  return token;
}

export function popOverlay(token: symbol): void {
  const index = stack.indexOf(token);
  if (index >= 0) stack.splice(index, 1);
}

export function isTopOverlay(token: symbol): boolean {
  return stack[stack.length - 1] === token;
}
