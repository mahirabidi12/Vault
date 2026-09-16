"use client";

import * as React from "react";
import { Check, Copy } from "lucide-react";
import { Button } from "@/components/ui/button";
import { cn } from "@/lib/utils";

export function CopyButton({ value, className, label }: { value: string; className?: string; label?: string }) {
  const [copied, setCopied] = React.useState(false);

  async function onCopy() {
    try {
      await navigator.clipboard.writeText(value);
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    } catch {
      // clipboard API unavailable; silently ignore
    }
  }

  return (
    <Button
      type="button"
      variant="ghost"
      size="sm"
      onClick={onCopy}
      className={cn("gap-1.5 font-mono text-xs", className)}
      aria-label={label ?? "Copy to clipboard"}
    >
      {copied ? <Check className="size-3.5 text-safe" /> : <Copy className="size-3.5" />}
      {copied ? "Copied" : (label ?? "Copy")}
    </Button>
  );
}
