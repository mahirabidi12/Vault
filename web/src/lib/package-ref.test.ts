import { describe, expect, it } from "vitest";
import { parsePackageQuery } from "@/lib/package-ref";

describe("parsePackageQuery", () => {
  it("leaves a plain name alone", () => {
    expect(parsePackageQuery("kind-of")).toEqual({ name: "kind-of", version: undefined });
  });

  it("splits name@version", () => {
    expect(parsePackageQuery("kind-of@6.0.3")).toEqual({ name: "kind-of", version: "6.0.3" });
  });

  it("does not split a bare scoped name", () => {
    expect(parsePackageQuery("@babel/core")).toEqual({ name: "@babel/core", version: undefined });
  });

  it("splits a scoped name with a version", () => {
    expect(parsePackageQuery("@babel/core@7.2.0")).toEqual({ name: "@babel/core", version: "7.2.0" });
  });

  it("trims surrounding whitespace", () => {
    expect(parsePackageQuery("  kind-of@6.0.3  ")).toEqual({ name: "kind-of", version: "6.0.3" });
  });

  it("treats a trailing bare @ as no version", () => {
    expect(parsePackageQuery("kind-of@")).toEqual({ name: "kind-of", version: undefined });
  });
});
