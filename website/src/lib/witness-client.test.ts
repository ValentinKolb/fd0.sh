import { afterEach, describe, expect, test } from "bun:test";
import { fetchCbor } from "./witness-client";

const servers: ReturnType<typeof Bun.serve>[] = [];

afterEach(() => {
  for (const server of servers.splice(0)) server.stop(true);
});

describe("fetchCbor", () => {
  test("does not follow redirects to a private destination", async () => {
    let destinationRequests = 0;
    const destination = Bun.serve({
      port: 0,
      fetch() {
        destinationRequests++;
        return new Response();
      },
    });
    servers.push(destination);

    const source = Bun.serve({
      port: 0,
      fetch() {
        return new Response(null, {
          status: 307,
          headers: { Location: destination.url.toString() },
        });
      },
    });
    servers.push(source);

    await expect(fetchCbor(source.url.toString(), AbortSignal.timeout(1000))).rejects.toThrow(
      "307",
    );
    expect(destinationRequests).toBe(0);
  });

  test("rejects streamed responses over one MiB", async () => {
    const server = Bun.serve({
      port: 0,
      fetch() {
        const stream = new ReadableStream<Uint8Array>({
          start(controller) {
            controller.enqueue(new Uint8Array(1 << 20));
            controller.enqueue(new Uint8Array([0]));
            controller.close();
          },
        });
        return new Response(stream, {
          headers: { "Content-Type": "application/cbor" },
        });
      },
    });
    servers.push(server);

    await expect(fetchCbor(server.url.toString(), AbortSignal.timeout(1000))).rejects.toThrow(
      "response exceeds",
    );
  });
});
