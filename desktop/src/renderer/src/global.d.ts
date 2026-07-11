import type { DesktopAPI } from "../../shared/contracts";

declare global {
  interface Window {
    fd0: DesktopAPI;
  }
}

export {};
