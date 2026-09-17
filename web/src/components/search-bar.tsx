"use client";

import * as React from "react";
import { useRouter } from "next/navigation";
import { Search } from "lucide-react";
import { Input } from "@/components/ui/input";
import { cn } from "@/lib/utils";

export function SearchBar({
  variant = "compact",
  className,
  placeholder = "Search a package, e.g. express or @babel/core",
  autoFocus,
}: {
  variant?: "hero" | "compact";
  className?: string;
  placeholder?: string;
  autoFocus?: boolean;
}) {
  const router = useRouter();
  const [value, setValue] = React.useState("");

  function onSubmit(e: React.FormEvent) {
    e.preventDefault();
    const q = value.trim();
    if (!q) return;
    router.push(`/search?q=${encodeURIComponent(q)}`);
  }

  return (
    <form onSubmit={onSubmit} className={cn("relative w-full", className)}>
      <Search
        className={cn(
          "pointer-events-none absolute top-1/2 -translate-y-1/2 text-muted-foreground",
          variant === "hero" ? "left-4 size-5" : "left-3 size-4"
        )}
      />
      <Input
        value={value}
        onChange={(e) => setValue(e.target.value)}
        placeholder={placeholder}
        autoFocus={autoFocus}
        className={cn(
          variant === "hero"
            ? "h-14 rounded-lg border-border/80 bg-card/80 pl-12 pr-4 text-base shadow-lg shadow-black/[0.03] backdrop-blur-sm focus-visible:ring-4 focus-visible:ring-brand/15 dark:shadow-black/20"
            : "h-9 rounded-full pl-9 text-sm"
        )}
      />
    </form>
  );
}
