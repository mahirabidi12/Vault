import { describe, expect, it } from "vitest";
import { parseSpec } from "../src/spec.js";

describe("parseSpec", () => {
  it("parses a bare name", () => {
    expect(parseSpec("lodash")).toEqual({ name: "lodash", version: undefined });
  });

  it("parses name@version", () => {
    expect(parseSpec("lodash@4.17.21")).toEqual({ name: "lodash", version: "4.17.21" });
  });

  it("parses a bare scoped name", () => {
    expect(parseSpec("@babel/core")).toEqual({ name: "@babel/core", version: undefined });
  });

  it("parses a scoped name with a version", () => {
    expect(parseSpec("@babel/core@7.24.0")).toEqual({ name: "@babel/core", version: "7.24.0" });
  });
});
