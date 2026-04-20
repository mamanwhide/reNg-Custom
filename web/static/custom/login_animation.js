/**
 * paraKang Login Page — Particle Network Animation
 * Generates an animated particle network background for visual appeal
 */

class ParticleNetwork {
  constructor(canvasId = 'particle-canvas') {
    this.canvas = document.getElementById(canvasId);
    if (!this.canvas) {
      console.warn('Particle canvas not found');
      return;
    }

    this.ctx = this.canvas.getContext('2d');
    this.particles = [];
    this.mousePos = { x: 0, y: 0 };
    this.animationId = null;

    // Configuration
    this.config = {
      particleCount: 50,
      particleRadius: 1.5,
      particleOpacity: 0.5,
      particleSpeed: 0.5,
      connectionDistance: 150,
      connectionOpacity: 0.2,
      backgroundColor: 'transparent',
    };

    this.init();
  }

  init() {
    this.resizeCanvas();
    this.createParticles();
    this.setupEventListeners();
    this.animate();
  }

  resizeCanvas() {
    this.canvas.width = this.canvas.offsetWidth;
    this.canvas.height = this.canvas.offsetHeight;
  }

  createParticles() {
    this.particles = [];
    for (let i = 0; i < this.config.particleCount; i++) {
      this.particles.push({
        x: Math.random() * this.canvas.width,
        y: Math.random() * this.canvas.height,
        vx: (Math.random() - 0.5) * this.config.particleSpeed,
        vy: (Math.random() - 0.5) * this.config.particleSpeed,
        radius: this.config.particleRadius,
        opacity: Math.random() * this.config.particleOpacity + 0.2,
      });
    }
  }

  setupEventListeners() {
    window.addEventListener('resize', () => this.handleResize());
    document.addEventListener('mousemove', (e) => this.handleMouseMove(e));
    document.addEventListener('mouseleave', () => this.handleMouseLeave());
  }

  handleResize() {
    this.resizeCanvas();
    this.createParticles();
  }

  handleMouseMove(e) {
    this.mousePos = {
      x: e.clientX,
      y: e.clientY,
    };
  }

  handleMouseLeave() {
    this.mousePos = { x: -1000, y: -1000 };
  }

  updateParticles() {
    for (let particle of this.particles) {
      // Update position
      particle.x += particle.vx;
      particle.y += particle.vy;

      // Bounce off edges
      if (particle.x < 0 || particle.x > this.canvas.width) {
        particle.vx *= -1;
        particle.x = Math.max(0, Math.min(this.canvas.width, particle.x));
      }
      if (particle.y < 0 || particle.y > this.canvas.height) {
        particle.vy *= -1;
        particle.y = Math.max(0, Math.min(this.canvas.height, particle.y));
      }

      // Slight random wiggle
      particle.vx += (Math.random() - 0.5) * 0.1;
      particle.vy += (Math.random() - 0.5) * 0.1;

      // Limit speed
      const speed = Math.sqrt(particle.vx ** 2 + particle.vy ** 2);
      if (speed > this.config.particleSpeed * 2) {
        particle.vx = (particle.vx / speed) * this.config.particleSpeed;
        particle.vy = (particle.vy / speed) * this.config.particleSpeed;
      }

      // Opacity animation
      const baseOpacity = Math.random() * this.config.particleOpacity + 0.2;
      particle.opacity = Math.max(
        0.1,
        Math.min(0.8, particle.opacity + (Math.random() - 0.5) * 0.05)
      );
    }
  }

  drawParticles() {
    for (let particle of this.particles) {
      this.ctx.fillStyle = `rgba(99, 102, 241, ${particle.opacity})`;
      this.ctx.beginPath();
      this.ctx.arc(particle.x, particle.y, particle.radius, 0, Math.PI * 2);
      this.ctx.fill();
    }
  }

  drawConnections() {
    for (let i = 0; i < this.particles.length; i++) {
      for (let j = i + 1; j < this.particles.length; j++) {
        const dx = this.particles[i].x - this.particles[j].x;
        const dy = this.particles[i].y - this.particles[j].y;
        const distance = Math.sqrt(dx * dx + dy * dy);

        if (distance < this.config.connectionDistance) {
          const opacity =
            (1 - distance / this.config.connectionDistance) *
            this.config.connectionOpacity;
          this.ctx.strokeStyle = `rgba(99, 102, 241, ${opacity})`;
          this.ctx.lineWidth = 0.5;
          this.ctx.beginPath();
          this.ctx.moveTo(this.particles[i].x, this.particles[i].y);
          this.ctx.lineTo(this.particles[j].x, this.particles[j].y);
          this.ctx.stroke();
        }
      }

      // Connection to mouse
      const dx = this.particles[i].x - this.mousePos.x;
      const dy = this.particles[i].y - this.mousePos.y;
      const distance = Math.sqrt(dx * dx + dy * dy);

      if (distance < this.config.connectionDistance * 1.5) {
        const opacity =
          (1 - distance / (this.config.connectionDistance * 1.5)) *
          this.config.connectionOpacity *
          1.5;
        this.ctx.strokeStyle = `rgba(99, 102, 241, ${opacity})`;
        this.ctx.lineWidth = 1;
        this.ctx.beginPath();
        this.ctx.moveTo(this.particles[i].x, this.particles[i].y);
        this.ctx.lineTo(this.mousePos.x, this.mousePos.y);
        this.ctx.stroke();
      }
    }
  }

  clear() {
    this.ctx.fillStyle = this.config.backgroundColor;
    this.ctx.fillRect(0, 0, this.canvas.width, this.canvas.height);
  }

  animate() {
    this.clear();
    this.updateParticles();
    this.drawConnections();
    this.drawParticles();
    this.animationId = requestAnimationFrame(() => this.animate());
  }

  destroy() {
    if (this.animationId) {
      cancelAnimationFrame(this.animationId);
    }
  }
}

// Initialize on DOM ready
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', () => {
    window.particleNetwork = new ParticleNetwork('particle-canvas');
  });
} else {
  window.particleNetwork = new ParticleNetwork('particle-canvas');
}

// Cleanup on page unload
window.addEventListener('beforeunload', () => {
  if (window.particleNetwork) {
    window.particleNetwork.destroy();
  }
});
