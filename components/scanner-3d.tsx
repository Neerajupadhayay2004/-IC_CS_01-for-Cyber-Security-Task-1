"use client"

import { useRef, useMemo } from "react"
import { Canvas, useFrame } from "@react-three/fiber"
import { OrbitControls, Sphere, Ring } from "@react-three/drei"
import * as THREE from "three"

function ScannerSphere() {
  const sphereRef = useRef<THREE.Mesh>(null)
  const ringsRef = useRef<THREE.Group>(null)
  const scanLineRef = useRef<THREE.Mesh>(null)
  const orbitRef = useRef<THREE.Group>(null)
  const pulseRef = useRef<THREE.Mesh>(null)

  useFrame((state) => {
    const time = state.clock.elapsedTime

    if (sphereRef.current) {
      sphereRef.current.rotation.y += 0.003
      sphereRef.current.rotation.x = Math.sin(time * 0.3) * 0.1
    }

    if (ringsRef.current) {
      ringsRef.current.rotation.y += 0.015
      ringsRef.current.rotation.x = Math.sin(time * 0.5) * 0.3
      ringsRef.current.rotation.z = Math.cos(time * 0.3) * 0.2
    }

    if (scanLineRef.current) {
      scanLineRef.current.position.y = Math.sin(time * 2) * 2.5
      scanLineRef.current.material.opacity = 0.5 + Math.sin(time * 4) * 0.3
    }

    if (orbitRef.current) {
      orbitRef.current.rotation.y = time * 0.5
    }

    if (pulseRef.current) {
      const scale = 1 + Math.sin(time * 2) * 0.1
      pulseRef.current.scale.set(scale, scale, scale)
      pulseRef.current.material.opacity = 0.15 + Math.sin(time * 2) * 0.05
    }
  })

  const wireframeGeometry = useMemo(() => {
    const geo = new THREE.SphereGeometry(2, 32, 32)
    return new THREE.WireframeGeometry(geo)
  }, [])

  const hexagonGeometry = useMemo(() => {
    const shape = new THREE.Shape()
    for (let i = 0; i < 6; i++) {
      const angle = (i / 6) * Math.PI * 2
      const x = Math.cos(angle) * 0.3
      const y = Math.sin(angle) * 0.3
      if (i === 0) shape.moveTo(x, y)
      else shape.lineTo(x, y)
    }
    shape.closePath()
    return new THREE.ShapeGeometry(shape)
  }, [])

  return (
    <group>
      {/* Pulsing outer sphere */}
      <Sphere args={[2.8, 32, 32]} ref={pulseRef}>
        <meshBasicMaterial color="#60a5fa" transparent opacity={0.15} wireframe />
      </Sphere>

      {/* Main wireframe sphere with gradient effect */}
      <lineSegments geometry={wireframeGeometry} ref={sphereRef}>
        <lineBasicMaterial color="#60a5fa" transparent opacity={0.4} />
      </lineSegments>

      {/* Inner glowing core */}
      <Sphere args={[1.8, 32, 32]}>
        <meshBasicMaterial color="#3b82f6" transparent opacity={0.15} wireframe />
      </Sphere>

      {/* Central energy core */}
      <Sphere args={[0.5, 16, 16]}>
        <meshBasicMaterial color="#60a5fa" transparent opacity={0.8} />
      </Sphere>

      {/* Orbiting hexagons */}
      <group ref={orbitRef}>
        {[0, 60, 120, 180, 240, 300].map((angle, i) => (
          <mesh
            key={i}
            position={[Math.cos((angle * Math.PI) / 180) * 3.5, 0, Math.sin((angle * Math.PI) / 180) * 3.5]}
            rotation={[0, 0, 0]}
            geometry={hexagonGeometry}
          >
            <meshBasicMaterial
              color={i % 2 === 0 ? "#60a5fa" : "#a78bfa"}
              transparent
              opacity={0.6}
              side={THREE.DoubleSide}
            />
          </mesh>
        ))}
      </group>

      {/* Multiple scanning rings with different speeds */}
      <group ref={ringsRef}>
        <Ring args={[2.5, 2.6, 64]} rotation={[Math.PI / 2, 0, 0]}>
          <meshBasicMaterial color="#60a5fa" transparent opacity={0.7} side={THREE.DoubleSide} />
        </Ring>
        <Ring args={[3, 3.1, 64]} rotation={[Math.PI / 3, 0, 0]}>
          <meshBasicMaterial color="#a78bfa" transparent opacity={0.5} side={THREE.DoubleSide} />
        </Ring>
        <Ring args={[3.5, 3.6, 64]} rotation={[Math.PI / 4, 0, 0]}>
          <meshBasicMaterial color="#fb923c" transparent opacity={0.4} side={THREE.DoubleSide} />
        </Ring>
        <Ring args={[4, 4.1, 64]} rotation={[-Math.PI / 6, 0, 0]}>
          <meshBasicMaterial color="#34d399" transparent opacity={0.3} side={THREE.DoubleSide} />
        </Ring>
      </group>

      {/* Vertical scanning beam */}
      <mesh ref={scanLineRef} position={[0, 0, 0]}>
        <planeGeometry args={[8, 0.15]} />
        <meshBasicMaterial color="#60a5fa" transparent opacity={0.8} />
      </mesh>

      {/* Horizontal scanning beam */}
      <mesh position={[0, 0, 0]} rotation={[0, 0, Math.PI / 2]}>
        <planeGeometry args={[8, 0.1]} />
        <meshBasicMaterial color="#a78bfa" transparent opacity={0.4} />
      </mesh>

      {/* Enhanced particle system */}
      <Points />
      <DataStreams />
    </group>
  )
}

function Points() {
  const pointsRef = useRef<THREE.Points>(null)

  const particles = useMemo(() => {
    const positions = new Float32Array(2000 * 3)
    const colors = new Float32Array(2000 * 3)

    for (let i = 0; i < 2000; i++) {
      const theta = Math.random() * Math.PI * 2
      const phi = Math.random() * Math.PI
      const radius = 2.2 + Math.random() * 1.5

      positions[i * 3] = radius * Math.sin(phi) * Math.cos(theta)
      positions[i * 3 + 1] = radius * Math.sin(phi) * Math.sin(theta)
      positions[i * 3 + 2] = radius * Math.cos(phi)

      const colorChoice = Math.random()
      if (colorChoice < 0.33) {
        colors[i * 3] = 0.38
        colors[i * 3 + 1] = 0.65
        colors[i * 3 + 2] = 0.98
      } else if (colorChoice < 0.66) {
        colors[i * 3] = 0.66
        colors[i * 3 + 1] = 0.55
        colors[i * 3 + 2] = 0.98
      } else {
        colors[i * 3] = 0.98
        colors[i * 3 + 1] = 0.57
        colors[i * 3 + 2] = 0.24
      }
    }
    return { positions, colors }
  }, [])

  useFrame((state) => {
    if (pointsRef.current) {
      pointsRef.current.rotation.y = state.clock.elapsedTime * 0.08
      pointsRef.current.rotation.x = Math.sin(state.clock.elapsedTime * 0.2) * 0.2
    }
  })

  return (
    <points ref={pointsRef}>
      <bufferGeometry>
        <bufferAttribute
          attach="attributes-position"
          count={particles.positions.length / 3}
          array={particles.positions}
          itemSize={3}
        />
        <bufferAttribute
          attach="attributes-color"
          count={particles.colors.length / 3}
          array={particles.colors}
          itemSize={3}
        />
      </bufferGeometry>
      <pointsMaterial size={0.03} vertexColors transparent opacity={0.8} sizeAttenuation />
    </points>
  )
}

function DataStreams() {
  const streamsRef = useRef<THREE.Group>(null)

  useFrame((state) => {
    if (streamsRef.current) {
      streamsRef.current.rotation.y = state.clock.elapsedTime * 0.3
    }
  })

  const streamPositions = useMemo(() => {
    const streams = []
    for (let i = 0; i < 8; i++) {
      const angle = (i / 8) * Math.PI * 2
      streams.push({
        x: Math.cos(angle) * 2.5,
        z: Math.sin(angle) * 2.5,
        color: i % 2 === 0 ? "#60a5fa" : "#a78bfa",
      })
    }
    return streams
  }, [])

  return (
    <group ref={streamsRef}>
      {streamPositions.map((stream, i) => (
        <mesh key={i} position={[stream.x, 0, stream.z]}>
          <cylinderGeometry args={[0.02, 0.02, 5, 8]} />
          <meshBasicMaterial color={stream.color} transparent opacity={0.3} />
        </mesh>
      ))}
    </group>
  )
}

export function Scanner3D() {
  return (
    <div className="w-full h-full bg-gradient-to-b from-background via-background/95 to-primary/5">
      <Canvas camera={{ position: [0, 0, 10], fov: 50 }} gl={{ antialias: true, alpha: true }}>
        <color attach="background" args={["#0a0a0a"]} />
        <fog attach="fog" args={["#0a0a0a", 5, 20]} />

        <ambientLight intensity={0.3} />
        <pointLight position={[10, 10, 10]} intensity={1.5} color="#60a5fa" />
        <pointLight position={[-10, -10, -10]} intensity={0.8} color="#a78bfa" />
        <pointLight position={[0, 10, 0]} intensity={0.5} color="#fb923c" />
        <spotLight position={[0, 15, 0]} angle={0.3} penumbra={1} intensity={1} color="#60a5fa" />

        <ScannerSphere />
        <OrbitControls
          enableZoom={false}
          enablePan={false}
          autoRotate
          autoRotateSpeed={0.8}
          minPolarAngle={Math.PI / 3}
          maxPolarAngle={Math.PI / 1.5}
        />
      </Canvas>
    </div>
  )
}
