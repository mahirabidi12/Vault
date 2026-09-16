import { cn } from "@/lib/utils";

export function Logo({ className }: { className?: string }) {
  return (
    <svg
      viewBox="0 0 32 32"
      fill="none"
      className={cn("size-6", className)}
      aria-hidden="true"
    >
      <path
        d="M16 2.5 27.5 7v8.2c0 8.1-5 13.9-11.5 16.3C9.5 29.1 4.5 23.3 4.5 15.2V7L16 2.5Z"
        fill="url(#pkgguard-logo-grad)"
      />
      <path
        d="M16 2.5 27.5 7v8.2c0 8.1-5 13.9-11.5 16.3C9.5 29.1 4.5 23.3 4.5 15.2V7L16 2.5Z"
        stroke="currentColor"
        strokeOpacity="0.15"
      />
      <path
        d="M11 16.2 14.4 19.6 21.5 12.5"
        stroke="white"
        strokeWidth="2.4"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
      <defs>
        <linearGradient id="pkgguard-logo-grad" x1="4.5" y1="2.5" x2="27.5" y2="31.5" gradientUnits="userSpaceOnUse">
          <stop stopColor="var(--brand)" />
          <stop offset="1" stopColor="var(--brand-2)" />
        </linearGradient>
      </defs>
    </svg>
  );
}
