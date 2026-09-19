"use client";

import { ApiError } from "@/components/api-error";

export default function SearchError(props: { error: Error; reset: () => void }) {
  return <ApiError {...props} />;
}
