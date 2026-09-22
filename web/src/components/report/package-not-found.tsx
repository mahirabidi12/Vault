import Link from "next/link";
import { PackageX } from "lucide-react";
import { Button } from "@/components/ui/button";

/** Shown when the backend confirms a name doesn't exist on npm at all — not a scan failure, not "not scanned yet". */
export function PackageNotFound({ name, version }: { name: string; version?: string }) {
  return (
    <div className="mx-auto flex max-w-lg flex-col items-center gap-4 px-4 py-24 text-center">
      <PackageX className="size-10 text-muted-foreground" />
      <h1 className="text-xl font-semibold tracking-tight">Package not found</h1>
      <p className="font-mono text-sm text-muted-foreground">
        {name}
        {version ? `@${version}` : ""}
      </p>
      <p className="max-w-sm text-sm text-muted-foreground">
        There&apos;s no package by this name on npm. Check the spelling, or search for it below.
      </p>
      <Button variant="outline" render={<Link href="/search" />} nativeButton={false}>
        Search again
      </Button>
    </div>
  );
}
