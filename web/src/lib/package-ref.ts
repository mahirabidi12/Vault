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
