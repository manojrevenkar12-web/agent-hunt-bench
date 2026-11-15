import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen } from "@testing-library/react";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import { App } from "./App";

const data = JSON.parse(readFileSync(resolve(__dirname, "../../public/data/console.json"), "utf8"));

function mount(fetchImpl: typeof fetch) {
  vi.stubGlobal("fetch", fetchImpl);
  return render(
    <QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}>
      <App />
    </QueryClientProvider>,
  );
}

afterEach(() => vi.unstubAllGlobals());

describe("console", () => {
  it("shows a skeleton, then the platform's numbers from the report", async () => {
    mount(async () => new Response(JSON.stringify(data)));
    expect(screen.getByLabelText("Loading the console")).toBeTruthy();
    const n = data.environment.campaigns;
    expect(await screen.findByText(`${data.designs.platform.before_impact} of ${n}`)).toBeTruthy();
  });

  it("moves to another design's numbers when it is chosen", async () => {
    mount(async () => new Response(JSON.stringify(data)));
    fireEvent.click(await screen.findByRole("radio", { name: data.names.siem_basic }));
    expect(await screen.findByText(`${data.designs.siem_basic.before_impact} of ${data.environment.campaigns}`)).toBeTruthy();
    expect(screen.getByRole("radio", { name: data.names.siem_basic }).getAttribute("aria-checked")).toBe("true");
  });

  it("filters detections by source and opens the case detail", async () => {
    mount(async () => new Response(JSON.stringify(data)));
    fireEvent.click(await screen.findByRole("tab", { name: "Agents" }));
    expect(screen.getAllByText(/agent_/).length).toBeGreaterThan(0);
    fireEvent.click(screen.getByRole("button", { name: /Show the model's claims/ }));
    expect(await screen.findByText(/Containment planned at confirmation/)).toBeTruthy();
  });

  it("explains a failed load and retries", async () => {
    let calls = 0;
    mount(async () => {
      calls += 1;
      return calls === 1 ? new Response("", { status: 503 }) : new Response(JSON.stringify(data));
    });
    expect(await screen.findByRole("alert")).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "Retry" }));
    expect(await screen.findByText(`${data.designs.platform.before_impact} of ${data.environment.campaigns}`)).toBeTruthy();
  });
});
