"use client";

import * as React from "react";
import { Canvas, useFrame } from "@react-three/fiber";
import { Float, MeshDistortMaterial, Sparkles, Environment } from "@react-three/drei";
import * as THREE from "three";
import { useTheme } from "next-themes";

function CoreShield() {
  const ref = React.useRef<THREE.Mesh>(null);
  useFrame((state) => {
    if (!ref.current) return;
    ref.current.rotation.y = state.clock.elapsedTime * 0.18;
    ref.current.rotation.x = Math.sin(state.clock.elapsedTime * 0.3) * 0.15;
  });

  return (
    <Float speed={1.6} rotationIntensity={0.5} floatIntensity={1.1}>
      <mesh ref={ref}>
        <icosahedronGeometry args={[1.35, 8]} />
        <MeshDistortMaterial
          color="#6d4aff"
          attach="material"
          distort={0.32}
          speed={1.8}
          roughness={0.15}
          metalness={0.6}
          emissive="#4f2fd6"
          emissiveIntensity={0.25}
        />
      </mesh>
    </Float>
  );
}

function OrbitNode({
  radius,
  speed,
  size,
  color,
  offset,
}: {
  radius: number;
  speed: number;
  size: number;
  color: string;
  offset: number;
}) {
  const ref = React.useRef<THREE.Mesh>(null);
  useFrame((state) => {
    if (!ref.current) return;
    const t = state.clock.elapsedTime * speed + offset;
    ref.current.position.set(Math.cos(t) * radius, Math.sin(t * 0.7) * 0.6, Math.sin(t) * radius);
  });
  return (
    <mesh ref={ref}>
      <octahedronGeometry args={[size, 0]} />
      <meshStandardMaterial color={color} emissive={color} emissiveIntensity={0.5} roughness={0.3} />
    </mesh>
  );
}

function Scene() {
  const { resolvedTheme } = useTheme();
  const dark = resolvedTheme !== "light";

  return (
    <>
      <ambientLight intensity={dark ? 0.5 : 0.9} />
      <directionalLight position={[3, 4, 2]} intensity={1.2} />
      <pointLight position={[-3, -2, -2]} intensity={0.6} color="#4fd6ff" />

      <CoreShield />
      <OrbitNode radius={2.6} speed={0.5} size={0.16} color="#3ecf7a" offset={0} />
      <OrbitNode radius={2.9} speed={0.35} size={0.13} color="#f2b84b" offset={2.1} />
      <OrbitNode radius={2.3} speed={0.62} size={0.14} color="#3ecf7a" offset={4.2} />
      <OrbitNode radius={3.2} speed={0.28} size={0.1} color="#ff5c5c" offset={1.1} />

      <Sparkles count={60} scale={5.5} size={2} speed={0.3} color="#8b7bff" opacity={0.5} />
      <Environment preset={dark ? "city" : "apartment"} environmentIntensity={0.5} />
    </>
  );
}

export function HeroScene() {
  const [reducedMotion, setReducedMotion] = React.useState(false);

  React.useEffect(() => {
    const mq = window.matchMedia("(prefers-reduced-motion: reduce)");
    // eslint-disable-next-line react-hooks/set-state-in-effect
    setReducedMotion(mq.matches);
    const onChange = () => setReducedMotion(mq.matches);
    mq.addEventListener("change", onChange);
    return () => mq.removeEventListener("change", onChange);
  }, []);

  if (reducedMotion) return null;

  return (
    <Canvas
      dpr={[1, 1.75]}
      camera={{ position: [0, 0, 6.5], fov: 42 }}
      gl={{ antialias: true, alpha: true }}
      className="!absolute inset-0"
    >
      <React.Suspense fallback={null}>
        <Scene />
      </React.Suspense>
    </Canvas>
  );
}
