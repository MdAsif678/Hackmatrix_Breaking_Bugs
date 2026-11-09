// Hero background: a slow field of contour lines (the web's "signal") and a lens that follows the pointer and
// reveals the lines in blue, slightly magnified. Plain WebGL, one full-screen triangle, no libraries.
// Pauses off screen and in hidden tabs; one still frame under reduced motion; hidden without WebGL. Owner: P1.
import { useEffect, useRef } from 'react'
import { prefersReducedMotion } from './smooth'

const FRAG = /* glsl */ `
uniform vec2 uRes;
uniform float uTime;
uniform vec2 uMouse;
uniform float uLens;
uniform float uIntro;
uniform float uLine;   // line thickness in canvas pixels (scaled with resolution)

float hash(vec2 p) { p = fract(p * vec2(123.34, 456.21)); p += dot(p, p + 45.32); return fract(p.x * p.y); }
float noise(vec2 p) {
  vec2 i = floor(p), f = fract(p);
  vec2 u = f * f * (3.0 - 2.0 * f);
  return mix(mix(hash(i), hash(i + vec2(1.0, 0.0)), u.x), mix(hash(i + vec2(0.0, 1.0)), hash(i + vec2(1.0, 1.0)), u.x), u.y);
}
float fbm(vec2 p) {
  float v = 0.0, a = 0.5;
  for (int i = 0; i < 4; i++) { v += a * noise(p); p = p * 2.03 + vec2(1.7, 9.2); a *= 0.5; }
  return v;
}

void main() {
  vec2 frag = gl_FragCoord.xy;
  float d = length(frag - uMouse);
  float r = uLens * uIntro;
  float lens = 1.0 - smoothstep(r * 0.86, r, d);              // 1 inside the lens
  vec2 p = mix(frag, uMouse + (frag - uMouse) * 0.72, lens);  // magnify inside
  vec2 uv = p / uRes.y;
  float t = uTime * 0.035;

  vec2 q = vec2(fbm(uv * 1.6 + t), fbm(uv * 1.6 - t + 3.1));
  float f = fbm(uv * 1.7 + q * 1.3 + t * 0.4) * 26.0;
  float w = fwidth(f);
  float line = 1.0 - smoothstep(0.0, w * uLine, abs(fract(f) - 0.5));
  // Through the lens you see more: a second set of finer lines between the main ones.
  float f2 = f * 3.0;
  float w2 = fwidth(f2);
  float fine = 1.0 - smoothstep(0.0, w2 * uLine, abs(fract(f2) - 0.5));

  vec3 ground = vec3(0.039);
  vec3 outside = vec3(0.93) * 0.075;
  vec3 inside = vec3(0.553, 0.694, 1.0);
  vec3 col = ground + line * outside * (1.0 - lens) * uIntro;
  col += lens * uIntro * (line * inside * 0.85 + fine * inside * 0.22);
  col += lens * vec3(0.006, 0.012, 0.03) * uIntro;             // faint blue glass
  float rim = smoothstep(r * 0.94, r, d) * (1.0 - smoothstep(r, r * 1.03, d));
  col += rim * vec3(0.55, 0.69, 1.0) * 0.28 * uIntro;

  vec2 c = gl_FragCoord.xy / uRes - 0.5;
  col *= 1.0 - dot(c, c) * 1.1;                               // vignette
  gl_FragColor = vec4(col, 1.0);
}`

const VERT = `attribute vec2 a; void main() { gl_Position = vec4(a, 0.0, 1.0); }`

export function LensField({ className = '', play = true }: { className?: string; play?: boolean }) {
  const ref = useRef<HTMLCanvasElement>(null)
  // The field fades in from the moment `play` turns true (after the intro loader lifts).
  const playAt = useRef<number | null>(null)
  useEffect(() => {
    if (play && playAt.current === null) playAt.current = performance.now()
  }, [play])

  useEffect(() => {
    const canvas = ref.current!
    const gl = canvas.getContext('webgl', { antialias: false, alpha: false, powerPreference: 'low-power' })
    const deriv = gl?.getExtension('OES_standard_derivatives')
    if (!gl || !deriv || gl.isContextLost()) {
      canvas.style.display = 'none'
      return
    }
    const compile = (type: number, src: string) => {
      const s = gl.createShader(type)!
      gl.shaderSource(s, src)
      gl.compileShader(s)
      return s
    }
    const prog = gl.createProgram()!
    const vs = compile(gl.VERTEX_SHADER, VERT)
    // highp where the GPU has it: Android's mediump is a 16-bit float, too coarse for the noise and for pixel
    // coordinates on tall screens, which shows up as blocky, stair-stepped lines.
    const fs = compile(
      gl.FRAGMENT_SHADER,
      `#extension GL_OES_standard_derivatives : enable\n#ifdef GL_FRAGMENT_PRECISION_HIGH\nprecision highp float;\n#else\nprecision mediump float;\n#endif\n${FRAG}`,
    )
    gl.attachShader(prog, vs)
    gl.attachShader(prog, fs)
    gl.linkProgram(prog)
    gl.deleteShader(vs) // flagged now, freed together with the program
    gl.deleteShader(fs)
    if (!gl.getProgramParameter(prog, gl.LINK_STATUS)) {
      if (import.meta.env.DEV) console.warn('LensField shader:', gl.getProgramInfoLog(prog))
      canvas.style.display = 'none'
      return
    }
    gl.useProgram(prog)
    const buf = gl.createBuffer()
    gl.bindBuffer(gl.ARRAY_BUFFER, buf)
    gl.bufferData(gl.ARRAY_BUFFER, new Float32Array([-1, -1, 3, -1, -1, 3]), gl.STATIC_DRAW)
    const loc = gl.getAttribLocation(prog, 'a')
    gl.enableVertexAttribArray(loc)
    gl.vertexAttribPointer(loc, 2, gl.FLOAT, false, 0, 0)
    const u = (n: string) => gl.getUniformLocation(prog, n)
    const uRes = u('uRes'), uTime = u('uTime'), uMouse = u('uMouse'), uLens = u('uLens'), uIntro = u('uIntro'), uLine = u('uLine')

    const reduced = prefersReducedMotion()
    const coarse = window.matchMedia('(pointer: coarse)').matches
    // Resolution: phones get up to 2x (dense screens; a low-res canvas stretched over them looks blurry);
    // desktops up to 1.25x, sharp at normal viewing distance and still cheap on big screens.
    const scale = Math.min(window.devicePixelRatio || 1, coarse ? 2 : 1.25)
    let w = 0, h = 0
    const resize = () => {
      // Layout size, not getBoundingClientRect: the hero zooms with transforms, which must not change the resolution.
      w = Math.max(1, Math.round(canvas.clientWidth * scale))
      h = Math.max(1, Math.round(canvas.clientHeight * scale))
      canvas.width = w
      canvas.height = h
      gl.viewport(0, 0, w, h)
    }
    resize()
    // Resizing clears the canvas; under reduced motion nothing else redraws it, so draw the still frame again.
    const ro = new ResizeObserver(() => {
      resize()
      if (reduced) loop()
    })
    ro.observe(canvas)

    // Lens position: stays on the pointer while it is over the page; drifts on its own only when there is no
    // pointer (touch screens) or it has left the window.
    const pos = { x: w * 0.68, y: h * 0.5 }
    const target = { x: pos.x, y: pos.y }
    const pointer = { x: 0, y: 0, inside: false }
    const onMove = (e: PointerEvent) => {
      if (e.pointerType === 'touch') return
      pointer.x = e.clientX
      pointer.y = e.clientY
      pointer.inside = true
    }
    const onLeave = (e: PointerEvent) => {
      if (!e.relatedTarget) pointer.inside = false // left the window
    }
    window.addEventListener('pointermove', onMove, { passive: true })
    document.addEventListener('pointerout', onLeave, { passive: true })

    let visible = true
    const io = new IntersectionObserver(([entry]) => {
      visible = entry.isIntersecting
      if (visible) loop()
    })
    io.observe(canvas)

    const start = performance.now()
    let frame = 0
    const draw = (now: number) => {
      const t = (now - start) / 1000
      if (pointer.inside) {
        // Map the pointer into canvas pixels through the canvas's on-screen box, so zoom and parallax on the hero
        // never pull the lens off the cursor.
        const rect = canvas.getBoundingClientRect()
        target.x = ((pointer.x - rect.left) / rect.width) * w
        target.y = ((rect.bottom - pointer.y) / rect.height) * h
      } else {
        // Idle drift: right half on desktop; the empty top of the screen on phones, clear of the text.
        target.x = w * (coarse ? 0.55 + 0.22 * Math.sin(t * 0.21) : 0.62 + 0.18 * Math.sin(t * 0.21))
        target.y = h * (coarse ? 0.8 + 0.06 * Math.sin(t * 0.17 + 1.3) : 0.5 + 0.22 * Math.sin(t * 0.17 + 1.3))
      }
      // Close follow on a pointer (a touch of glide, no lag you can see); slower glide when drifting.
      const follow = pointer.inside ? 0.22 : 0.05
      pos.x += (target.x - pos.x) * follow
      pos.y += (target.y - pos.y) * follow
      const since = playAt.current === null ? 0 : (now - playAt.current) / 1000
      const intro = reduced ? 1 : Math.min(1, Math.max(0, since) / 1.8)
      gl.uniform2f(uRes, w, h)
      gl.uniform1f(uTime, reduced ? 12 : t + 12)
      gl.uniform2f(uMouse, pos.x, pos.y)
      gl.uniform1f(uLens, Math.min(w, h) * (coarse ? 0.22 : 0.17))
      gl.uniform1f(uIntro, 1 - Math.pow(1 - intro, 3))
      gl.uniform1f(uLine, 1.1 * scale + 0.4) // about 1.2 CSS px wide at any resolution
      gl.drawArrays(gl.TRIANGLES, 0, 3)
    }
    const loop = () => {
      cancelAnimationFrame(frame)
      const tick = (now: number) => {
        draw(now)
        if (!reduced && visible && !document.hidden) frame = requestAnimationFrame(tick)
      }
      frame = requestAnimationFrame(tick)
    }
    const onVisibility = () => !document.hidden && visible && loop()
    document.addEventListener('visibilitychange', onVisibility)
    loop()

    return () => {
      cancelAnimationFrame(frame)
      ro.disconnect()
      io.disconnect()
      window.removeEventListener('pointermove', onMove)
      document.removeEventListener('pointerout', onLeave)
      document.removeEventListener('visibilitychange', onVisibility)
      // Free GL objects but keep the context: a canvas has one context for life, and React may re-run this effect.
      gl.deleteBuffer(buf)
      gl.deleteProgram(prog)
    }
  }, [])

  return <canvas ref={ref} aria-hidden="true" className={`block h-full w-full ${className}`} />
}
