declare namespace chrome {
  namespace runtime {
    const id: string;
    const lastError: { message?: string } | undefined;

    type MessageSender = {
      documentId?: string;
      id?: string;
      frameId?: number;
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

}
