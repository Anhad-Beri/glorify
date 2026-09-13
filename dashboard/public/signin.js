const form = document.querySelector("#signin-form");
const errorMessage = document.querySelector("#signin-error");
const submitButton = form.querySelector("button[type='submit']");

function initializeHolographicOrbitBloom() {
  const canvas = document.querySelector(".auth-background");
  if (!canvas) return;
  const context = canvas.getContext("2d");
  const reducedMotion = window.matchMedia("(prefers-reduced-motion: reduce)");
  let width = 0;
  let height = 0;
  let dpr = 1;
  let frame = 0;

  function resize() {
    const bounds = canvas.getBoundingClientRect();
    dpr = Math.min(window.devicePixelRatio || 1, 2);
    width = Math.max(1, bounds.width);
    height = Math.max(1, bounds.height);
    canvas.width = Math.round(width * dpr);
    canvas.height = Math.round(height * dpr);
    context.setTransform(dpr, 0, 0, dpr, 0, 0);
  }

  function palette() {
    const styles = getComputedStyle(document.documentElement);
    return {
      background: styles.getPropertyValue("--shell").trim(),
      line: styles.getPropertyValue("--line").trim(),
      accent: styles.getPropertyValue("--accent").trim(),
      soft: "#62e8c8"
    };
  }

  function drawDiamond(x, y, size, angle, color, alpha) {
    context.save();
    context.translate(x, y);
    context.rotate(angle);
    context.scale(1, 0.72);
    context.strokeStyle = color;
    context.lineWidth = 1.1;
    for (let echo = 2; echo >= 0; echo -= 1) {
      const radius = size + echo * 5;
      context.globalAlpha = alpha * (echo ? 0.2 : 1);
      context.beginPath();
      context.moveTo(0, -radius);
      context.lineTo(radius, 0);
      context.lineTo(0, radius);
      context.lineTo(-radius, 0);
      context.closePath();
      context.stroke();
    }
    context.beginPath();
    context.moveTo(0, -size);
    context.lineTo(0, size);
    context.moveTo(-size, 0);
    context.lineTo(size, 0);
    context.stroke();
    context.restore();
  }

  function draw(time = 0) {
    const colors = palette();
    const animationTime = reducedMotion.matches ? 1800 : time * 0.12;
    context.fillStyle = colors.background;
    context.fillRect(0, 0, width, height);
    context.save();
    context.translate(width * 0.5, height * 0.5);
    context.scale(1.1, 1.1);
    context.translate(width * -0.5, height * -0.5);
    const centerX = width * 0.5;
    const centerY = height * 0.5;
    const orbitX = Math.min(width * 0.34, height * 0.8);
    const orbitY = height * 0.31;
    context.strokeStyle = colors.line;
    context.globalAlpha = 0.28;
    context.beginPath();
    context.ellipse(centerX, centerY, orbitX, orbitY, -0.12, 0, Math.PI * 2);
    context.stroke();
    for (let index = 0; index < 8; index += 1) {
      const phase = index / 8 * Math.PI * 2 + animationTime * 0.00018;
      const depth = (Math.sin(phase) + 1) / 2;
      const x = centerX + Math.cos(phase) * orbitX;
      const y = centerY + Math.sin(phase) * orbitY;
      const breath = 1 + Math.sin(animationTime * 0.0007 + index * 0.9) * 0.24;
      drawDiamond(x, y, (10 + depth * 19) * breath, phase + animationTime * 0.00014, index % 3 ? colors.accent : colors.soft, 0.3 + depth * 0.62);
    }
    for (let ring = 0; ring < 4; ring += 1) {
      const pulse = 14 + ring * 13 + Math.sin(animationTime * 0.00062 + ring) * 5;
      context.strokeStyle = ring < 2 ? colors.soft : colors.accent;
      context.globalAlpha = 0.3 - ring * 0.045;
      context.beginPath();
      context.ellipse(centerX, centerY, pulse * 1.35, pulse * 0.48, animationTime * 0.00016 + ring * 0.42, 0, Math.PI * 2);
      context.stroke();
    }
    context.shadowColor = colors.accent;
    context.shadowBlur = 24;
    context.fillStyle = colors.accent;
    context.globalAlpha = 0.9;
    context.beginPath();
    context.arc(centerX, centerY, 4, 0, Math.PI * 2);
    context.fill();
    context.restore();
    context.shadowBlur = 0;
    context.globalAlpha = 1;
    frame = reducedMotion.matches ? 0 : window.requestAnimationFrame(draw);
  }

  function start() {
    window.cancelAnimationFrame(frame);
    resize();
    draw();
  }

  new ResizeObserver(start).observe(canvas);
  reducedMotion.addEventListener("change", start);
}

initializeHolographicOrbitBloom();

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  errorMessage.hidden = true;
  submitButton.disabled = true;
  submitButton.querySelector("span:first-child").textContent = "Signing in…";

  try {
    const response = await fetch("/api/signin", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        email: form.elements.email.value,
        password: form.elements.password.value
      })
    });
    const result = await response.json();
    if (!response.ok) throw new Error(result.error ?? "Unable to sign in");
    window.location.assign("/app");
  } catch (error) {
    errorMessage.textContent = error.message;
    errorMessage.hidden = false;
    submitButton.disabled = false;
    submitButton.querySelector("span:first-child").textContent = "Sign in";
  }
});
