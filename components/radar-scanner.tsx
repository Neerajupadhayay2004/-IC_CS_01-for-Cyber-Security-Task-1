"use client"

import { useEffect, useRef } from "react"

export function RadarScanner() {
  const canvasRef = useRef<HTMLCanvasElement>(null)

  useEffect(() => {
    const canvas = canvasRef.current
    if (!canvas) return

    const ctx = canvas.getContext("2d")
    if (!ctx) return

    let angle = 0
    const centerX = canvas.width / 2
    const centerY = canvas.height / 2
    const radius = Math.min(centerX, centerY) - 20

    const animate = () => {
      ctx.clearRect(0, 0, canvas.width, canvas.height)

      // Draw circles
      ctx.strokeStyle = "rgba(96, 165, 250, 0.2)"
      ctx.lineWidth = 1
      for (let i = 1; i <= 4; i++) {
        ctx.beginPath()
        ctx.arc(centerX, centerY, (radius / 4) * i, 0, Math.PI * 2)
        ctx.stroke()
      }

      // Draw crosshair
      ctx.beginPath()
      ctx.moveTo(centerX, centerY - radius)
      ctx.lineTo(centerX, centerY + radius)
      ctx.moveTo(centerX - radius, centerY)
      ctx.lineTo(centerX + radius, centerY)
      ctx.stroke()

      // Draw scanning beam
      const gradient = ctx.createRadialGradient(centerX, centerY, 0, centerX, centerY, radius)
      gradient.addColorStop(0, "rgba(96, 165, 250, 0.8)")
      gradient.addColorStop(0.5, "rgba(96, 165, 250, 0.3)")
      gradient.addColorStop(1, "rgba(96, 165, 250, 0)")

      ctx.save()
      ctx.translate(centerX, centerY)
      ctx.rotate(angle)
      ctx.beginPath()
      ctx.moveTo(0, 0)
      ctx.arc(0, 0, radius, 0, Math.PI / 6)
      ctx.closePath()
      ctx.fillStyle = gradient
      ctx.fill()
      ctx.restore()

      // Draw random blips
      ctx.fillStyle = "rgba(96, 165, 250, 0.8)"
      for (let i = 0; i < 5; i++) {
        const blipAngle = Math.random() * Math.PI * 2
        const blipRadius = Math.random() * radius
        const blipX = centerX + Math.cos(blipAngle) * blipRadius
        const blipY = centerY + Math.sin(blipAngle) * blipRadius

        ctx.beginPath()
        ctx.arc(blipX, blipY, 3, 0, Math.PI * 2)
        ctx.fill()
      }

      angle += 0.02
      requestAnimationFrame(animate)
    }

    animate()
  }, [])

  return (
    <canvas
      ref={canvasRef}
      width={300}
      height={300}
      className="w-full h-full"
      style={{ filter: "drop-shadow(0 0 20px rgba(96, 165, 250, 0.5))" }}
    />
  )
}
