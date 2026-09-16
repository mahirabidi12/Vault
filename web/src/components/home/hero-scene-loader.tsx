"use client";

import dynamic from "next/dynamic";

const HeroScene = dynamic(() => import("@/components/home/hero-scene").then((m) => m.HeroScene), {
  ssr: false,
});

export function HeroSceneLoader() {
  return <HeroScene />;
}
