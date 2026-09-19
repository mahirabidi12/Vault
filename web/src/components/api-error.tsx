"use client";

import Link from "next/link";
import { AlertTriangle } from "lucide-react";
import { Button } from "@/components/ui/button";

/** Friendly failure screen shared by the routes that call the API. */
export function ApiError({ error, reset }: { error: Error; reset: () => void }) {
  const busy = /busy right now/i.test(error.message);
  const known = busy || error.message.startsWith("PkgGuard API") || error.message.startsWith("Could not reach");
  return (
    <div className="mx-auto flex max-w-xl flex-col items-center gap-5 px-4 py-24 text-center">
      <span className="flex size-16 items-center justify-center rounded-2xl border border-suspicious/40 bg-suspicious/10 text-suspicious">
        <AlertTriangle className="size-8" />
      </span>
      <h1 className="font-display text-2xl font-semibold tracking-tight sm:text-3xl">{busy ? "PkgGuard is busy right now" : "Something went wrong"}</h1>
      <p className="text-sm leading-relaxed text-muted-foreground">
        {known ? error.message : "We couldn't load this page."}
        {busy && " Scans use up the shared capacity for a moment. Nothing is lost."}
      </p>
      <div className="flex gap-3">
        <Button onClick={reset}>Try again</Button>
        <Button variant="outline" render={<Link href="/" />} nativeButton={false}>
          Back home
        </Button>
      </div>
    </div>
  );
}
