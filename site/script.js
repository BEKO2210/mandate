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

  const nodes = [
    [90, 70],
    [280, 70],
    [280, 214],
    [280, 340],
    [470, 214],
    [470, 340]
  ];

  // The diagram has two legitimate paths after Mandate:
  // direct authorization (Mandate -> Upstream) and human step-up
  // (Mandate -> Human -> Upstream). Alternate cycles so the animation
  // demonstrates both without implying that human approval is mandatory.
  const directSequence = [0, 1, 2, 4, 5];
  const stepUpSequence = [0, 1, 2, 3, 4, 5];

  const routes = new Map([
    ["0-1", [[90, 70], [280, 70]]],
    ["1-2", [[280, 70], [280, 214]]],
    ["2-3", [[280, 214], [280, 340]]],
    ["2-4", [[280, 214], [470, 214]]],
    ["3-4", [[280, 340], [470, 340], [470, 214]]],
    ["4-5", [[470, 214], [470, 340]]]
  ]);

  const board = document.querySelectorAll(".stageboard [data-stage]");
  const list = document.querySelectorAll(".arch [data-stage]");
  const label = document.getElementById("stage-label");
  const packet = document.getElementById("packet");
  const media = window.matchMedia("(prefers-reduced-motion: reduce)");
  let reduce = media.matches;
  let runToken = 0;

  const delay = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

  const setPacket = ([x, y]) => {
    if (!packet) return;
    packet.setAttribute("cx", String(x));
    packet.setAttribute("cy", String(y));
  };

  const setStage = (i) => {
    board.forEach((el, idx) => el.classList.toggle("is-on", idx === i));
    list.forEach((el, idx) => el.classList.toggle("is-on", idx === i));
    if (label) {
      label.textContent = `Stage ${String(i + 1).padStart(2, "0")} · ${names[i]}`;
    }
  };

  const lerp = (a, b, t) => a + (b - a) * t;

  const moveSegment = (from, to, ms, token) => new Promise((resolve) => {
    if (!packet || reduce || token !== runToken) {
      resolve();
      return;
    }
    const [x0, y0] = from;
    const [x1, y1] = to;
    const start = performance.now();
    const step = (now) => {
      if (reduce || token !== runToken) {
        resolve();
        return;
      }
      const t = Math.min(1, (now - start) / ms);
      const eased = t * t * (3 - 2 * t);
      setPacket([lerp(x0, x1, eased), lerp(y0, y1, eased)]);
      if (t < 1) requestAnimationFrame(step);
      else resolve();
    };
    requestAnimationFrame(step);
  });

  const moveRoute = async (fromStage, toStage, totalMs, token) => {
    const waypoints = routes.get(`${fromStage}-${toStage}`);
    if (!waypoints || waypoints.length < 2) {
      setPacket(nodes[toStage]);
      return;
    }
    const lengths = [];
    let totalLength = 0;
    for (let i = 1; i < waypoints.length; i += 1) {
      const dx = waypoints[i][0] - waypoints[i - 1][0];
      const dy = waypoints[i][1] - waypoints[i - 1][1];
      const len = Math.hypot(dx, dy);
      lengths.push(len);
      totalLength += len;
    }
    for (let i = 1; i < waypoints.length; i += 1) {
      const ms = totalLength ? totalMs * (lengths[i - 1] / totalLength) : totalMs;
      await moveSegment(waypoints[i - 1], waypoints[i], ms, token);
      if (reduce || token !== runToken) return;
    }
  };

  const setReducedState = () => {
    runToken += 1;
    document.documentElement.classList.toggle("reduced", reduce);
    if (reduce) {
      setStage(2);
      setPacket(nodes[2]);
    }
  };

  const dwell = 900;
  const travel = 700;

  const runCycle = async (sequence, token) => {
    setPacket(nodes[sequence[0]]);
    if (packet) packet.style.opacity = "1";
    setStage(sequence[0]);
    await delay(dwell);

    for (let i = 1; i < sequence.length; i += 1) {
      if (reduce || token !== runToken) return;
      const from = sequence[i - 1];
      const to = sequence[i];
      await moveRoute(from, to, travel, token);
      if (reduce || token !== runToken) return;
      setStage(to);
      await delay(dwell);
    }

    // Reset invisibly rather than drawing a fake Receipt -> Principal edge.
    if (packet) packet.style.opacity = "0";
    setPacket(nodes[0]);
    await delay(140);
    if (packet) packet.style.opacity = "1";
  };

  const startFlow = async () => {
    const token = ++runToken;
    let stepUp = false;
    while (!reduce && token === runToken) {
      await runCycle(stepUp ? stepUpSequence : directSequence, token);
      stepUp = !stepUp;
    }
  };

  const handleMotionPreference = () => {
    reduce = media.matches;
    setReducedState();
    if (!reduce) startFlow();
  };

  if (typeof media.addEventListener === "function") {
    media.addEventListener("change", handleMotionPreference);
  }

  setReducedState();
  if (!reduce) startFlow();

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
