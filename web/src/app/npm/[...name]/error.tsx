"use client";

import { ApiError } from "@/components/api-error";

export default function PackageError(props: { error: Error; reset: () => void }) {
  return <ApiError {...props} />;
}
