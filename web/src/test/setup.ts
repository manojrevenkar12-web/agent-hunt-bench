import { cleanup } from "@testing-library/react";
import { afterEach } from "vitest";

// jsdom has no layout; layout animations call scrollTo while measuring.
window.scrollTo = () => {};
afterEach(() => cleanup());
