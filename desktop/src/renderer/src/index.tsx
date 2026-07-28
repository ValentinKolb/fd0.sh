import { render } from "solid-js/web";
import "@fontsource-variable/geist";
import "@fontsource-variable/geist-mono";
import App from "./App";
import { LargeTypeWindow } from "./features/LargeTypeWindow";
import { TerminalWindow } from "./features/TerminalWindow";
import { activateTheme, readTheme } from "./lib/theme";
import "./styles.css";

if (!window.fd0.terminalMode) {
  activateTheme(readTheme(localStorage, window.fd0.development));
}

/*
 * The floating large-type window loads this same bundle. The preload flag — not
 * the URL fragment — decides which surface mounts, so no in-page navigation or
 * crafted link can turn the main window into the large-type view or vice versa.
 */
render(
  () => window.fd0.terminalMode
    ? <TerminalWindow />
    : window.fd0.largeTypeMode
      ? <LargeTypeWindow />
      : <App />,
  document.getElementById("root")!,
);
