declare namespace chrome {
  namespace runtime {
    const id: string;
    const lastError: { message?: string } | undefined;

    type MessageSender = {
      documentId?: string;
      id?: string;
      frameId?: number;
      origin?: string;
      url?: string;
      tab?: tabs.Tab;
    };

    function sendNativeMessage<T = unknown>(
      application: string,
      message: unknown,
    ): Promise<T>;
    function sendMessage<T = unknown>(message: unknown): Promise<T>;

    const onMessage: {
      addListener(
        callback: (
          message: unknown,
          sender: MessageSender,
          sendResponse: (response: unknown) => void,
        ) => boolean | void,
      ): void;
      removeListener(
        callback: (
          message: unknown,
          sender: MessageSender,
          sendResponse: (response: unknown) => void,
        ) => boolean | void,
      ): void;
    };

    const onInstalled: {
      addListener(callback: () => void): void;
    };
  }

  namespace tabs {
    type Tab = { id?: number; url?: string };
    type MessageSendOptions = {
      documentId?: string;
      frameId?: number;
    };

    function sendMessage<T = unknown>(
      tabId: number,
      message: unknown,
      options?: MessageSendOptions,
    ): Promise<T>;
    function query(queryInfo: Record<string, unknown>): Promise<Tab[]>;
  }

  namespace action {
    const onClicked: {
      addListener(callback: (tab: tabs.Tab) => void | Promise<void>): void;
    };

    function setBadgeText(details: { tabId: number; text: string }): Promise<void>;
    function setBadgeBackgroundColor(details: {
      tabId: number;
      color: string;
    }): Promise<void>;
    function setTitle(details: { tabId: number; title: string }): Promise<void>;
  }

  namespace scripting {
    type InjectionResult<T = unknown> = {
      documentId?: string;
      frameId: number;
      result?: T;
    };

    function executeScript<T = unknown>(details: {
      target: {
        tabId: number;
        allFrames?: boolean;
        frameIds?: number[];
      };
      files?: string[];
      func?: () => T;
    }): Promise<InjectionResult<T>[]>;
  }

  namespace storage {
    const session: {
      get(
        keys?: string | string[] | null,
      ): Promise<Record<string, unknown>>;
      set(items: Record<string, unknown>): Promise<void>;
      remove(keys: string | string[]): Promise<void>;
    };
  }

  namespace alarms {
    type Alarm = { name: string };
    function create(
      name: string,
      alarmInfo: { when: number },
    ): Promise<void>;
    function clear(name: string): Promise<boolean>;
    const onAlarm: {
      addListener(callback: (alarm: Alarm) => void): void;
    };
  }
}
