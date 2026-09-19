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
        setTimeout(() => { copy.textContent = "Copy"; }, 1200);
      } catch (_) {}
    });
  }

  const board = document.querySelectorAll(".stageboard [data-stage]");
  const list = document.querySelectorAll(".arch [data-stage]");
  const label = document.getElementById("stage-label");
  const names = [
    "Principal signs a scoped grant",
    "Agent submits intent — no destination allowed",
    "Mandate evaluates policy, budget, route",
    "Human approval revalidates when required",
    "Trusted connector reaches the registered route",
    "Enforcer signs the execution receipt"
  ];
  if (board.length && !window.matchMedia("(prefers-reduced-motion: reduce)").matches) {
    let i = 0;
    const tick = () => {
      board.forEach((el, idx) => el.classList.toggle("is-on", idx === i));
      list.forEach((el, idx) => el.classList.toggle("is-on", idx === i));
      if (label) label.textContent = `Stage ${String(i + 1).padStart(2, "0")} · ${names[i]}`;
      i = (i + 1) % board.length;
    };
    tick();
    setInterval(tick, 1600);
  }

  if ("IntersectionObserver" in window) {
    const io = new IntersectionObserver((entries) => {
      entries.forEach((e) => {
        if (e.isIntersecting) {
          e.target.classList.add("in");
          io.unobserve(e.target);
        }
      });
    }, { threshold: 0.12 });
    document.querySelectorAll(".rise").forEach((el) => io.observe(el));
  }
})();
