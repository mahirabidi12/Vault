import type { Metadata } from "next";
import { PackageDirectory } from "@/components/packages/package-directory";

export const metadata: Metadata = {
  title: "Scan and browse packages",
  description: "Every package PkgGuard has scanned, with search. Can't find one? Scan it.",
};

export default function PackagesPage() {
  return <PackageDirectory />;
}
