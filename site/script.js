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

  const names = [
    "Principal signs a scoped grant",
    "Agent submits intent — no destination allowed",
    "Mandate evaluates policy, budget, and route",
    "Human approval only if required, then revalidation",
    "Trusted connector reaches the registered route",
    "Enforcer signs the execution receipt"
  ];
  const points = [
    [90, 70],
    [280, 70],
    [280, 214],
    [280, 340],
    [470, 214],
    [470, 340]
  ];

  const board = document.querySelectorAll(".stageboard [data-stage]");
  const list = document.querySelectorAll(".arch [data-stage]");
  const label = document.getElementById("stage-label");
  const packet = document.getElementById("packet");
  const reduce = window.matchMedia("(prefers-reduced-motion: reduce)").matches;

  const setStage = (i) => {
    board.forEach((el, idx) => el.classList.toggle("is-on", idx === i));
    list.forEach((el, idx) => el.classList.toggle("is-on", idx === i));
    if (label) label.textContent = `Stage ${String(i + 1).padStart(2, "0")} · ${names[i]}`;
    if (packet) {
      packet.setAttribute("cx", String(points[i][0]));
      packet.setAttribute("cy", String(points[i][1]));
    }
  };

  const lerp = (a, b, t) => a + (b - a) * t;
  const movePacket = (from, to, ms) => new Promise((resolve) => {
    if (!packet || reduce) { resolve(); return; }
    const [x0, y0] = points[from];
    const [x1, y1] = points[to];
    const start = performance.now();
    const step = (now) => {
      const t = Math.min(1, (now - start) / ms);
      const e = t * t * (3 - 2 * t);
      packet.setAttribute("cx", String(lerp(x0, x1, e)));
      packet.setAttribute("cy", String(lerp(y0, y1, e)));
      if (t < 1) requestAnimationFrame(step);
      else resolve();
    };
    requestAnimationFrame(step);
  });

  if (reduce) {
    document.documentElement.classList.add("reduced");
    setStage(2);
    return;
  }

  let active = 0;
  const dwell = 900;
  const travel = 700;
  const loop = async () => {
    setStage(active);
    await new Promise((r) => setTimeout(r, dwell));
    const next = (active + 1) % points.length;
    await movePacket(active, next, travel);
    active = next;
    loop();
  };
  loop();

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
