export interface Spec {
  name: string;
  version?: string;
}

/** Splits "foo", "foo@1.2.3" or "@scope/foo@1.2.3" into a name and an optional version. */
export function parseSpec(spec: string): Spec {
  const scoped = spec.startsWith("@");
  const body = scoped ? spec.slice(1) : spec;
  const at = body.indexOf("@");
  if (at === -1) return { name: spec };
  const name = scoped ? `@${body.slice(0, at)}` : body.slice(0, at);
  const version = body.slice(at + 1) || undefined;
  return { name, version };
}
