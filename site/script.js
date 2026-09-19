(() => {
  const menu = document.getElementById("menu");
  const links = document.getElementById("nav-links");
  if (menu && links) {
    menu.addEventListener("click", () => {
      const open = links.classList.toggle("open");
      menu.setAttribute("aria-expanded", String(open));
    });
    links.querySelectorAll("a").forEach((a) => {
      a.addEventListener("click", () => {
        links.classList.remove("open");
        menu.setAttribute("aria-expanded", "false");
      });
    });
  }

  const copy = document.querySelector("[data-copy]");
  const snippet = document.getElementById("snippet");
  if (copy && snippet) {
    copy.addEventListener("click", async () => {
      try {
        await navigator.clipboard.writeText(snippet.innerText);
        copy.textContent = "Copied";
        setTimeout(() => { copy.textContent = "Copy"; }, 1400);
      } catch (_) {}
    });
  }

  if ("IntersectionObserver" in window && !window.matchMedia("(prefers-reduced-motion: reduce)").matches) {
    const io = new IntersectionObserver((entries) => {
      entries.forEach((entry) => {
        if (entry.isIntersecting) {
          entry.target.style.animationPlayState = "running";
          io.unobserve(entry.target);
        }
      });
    }, { threshold: 0.12 });
    document.querySelectorAll(".reveal").forEach((el) => {
      el.style.animationPlayState = "paused";
      io.observe(el);
    });
  }

  const stage = document.querySelector(".hero-stage");
  if (stage && !window.matchMedia("(prefers-reduced-motion: reduce)").matches) {
    stage.addEventListener("pointermove", (e) => {
      const r = stage.getBoundingClientRect();
      const x = ((e.clientX - r.left) / r.width - 0.5) * 8;
      const y = ((e.clientY - r.top) / r.height - 0.5) * 8;
      stage.style.transform = `perspective(900px) rotateY(${x}deg) rotateX(${-y}deg)`;
    });
    stage.addEventListener("pointerleave", () => {
      stage.style.transform = "";
    });
  }
})();
