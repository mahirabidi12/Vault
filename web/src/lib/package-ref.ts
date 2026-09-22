/**
 * Helpers for turning an npm package name into route segments and back.
 * Scoped names ("@babel/core") contain a "/", so the report route is a
 * catch-all (`/npm/[...name]`) and each path part must be encoded on its own.
 */

export function nameToSegments(name: string): string[] {
  return name.split("/").filter(Boolean);
}

export function segmentsToName(segments: string[]): string {
  return segments.map((s) => decodeURIComponent(s)).join("/");
}

export function packageHref(name: string, version?: string | null): string {
  const path = nameToSegments(name).map(encodeURIComponent).join("/");
  const query = version ? `?version=${encodeURIComponent(version)}` : "";
  return `/npm/${path}${query}`;
}

export function isScopedName(name: string): boolean {
  return name.startsWith("@") && name.includes("/");
}

/**
 * Splits a user-typed "name@version" query into its parts. Splits on the
 * LAST "@", but only when something other than "@" precedes it — so a bare
 * scoped name ("@babel/core") is left alone, while a scoped name with a
 * version ("@babel/core@7.2.0") still splits correctly.
 */
export function parsePackageQuery(input: string): { name: string; version?: string } {
  const trimmed = input.trim();
  const at = trimmed.lastIndexOf("@");
  if (at > 0) {
    const version = trimmed.slice(at + 1).trim();
    return { name: trimmed.slice(0, at), version: version || undefined };
  }
  return { name: trimmed };
}
