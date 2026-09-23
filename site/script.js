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

  // Human step-up sits above the upstream, not below it: after the gate
  // the step-up path only ever moves forward (up to the human, then down
  // through the upstream to the receipt) and never crosses another stage.
  const nodes = [
    [90, 70],
    [280, 70],
    [280, 214],
    [470, 70],
    [470, 214],
    [470, 340]
  ];

  // Three legitimate endings after Mandate, taken in turn: direct
  // authorization (Mandate -> Upstream), human step-up (Mandate -> Human ->
  // Upstream), and denial, where the request stops at the gate. Showing the
  // denial is the point of the product; showing only successes would hide it.
  const directSequence = [0, 1, 2, 4, 5];
  const stepUpSequence = [0, 1, 2, 3, 4, 5];
  const deniedSequence = [0, 1, 2];

  const routes = new Map([
    ["0-1", [[90, 70], [280, 70]]],
    ["1-2", [[280, 70], [280, 214]]],
    ["2-3", [[280, 214], [378, 214], [378, 70], [470, 70]]],
    ["2-4", [[280, 214], [470, 214]]],
    ["3-4", [[470, 70], [470, 214]]],
    ["4-5", [[470, 214], [470, 340]]]
  ]);

  const board = document.querySelectorAll(".stageboard [data-stage]");
  const list = document.querySelectorAll(".arch [data-stage]");
  const label = document.getElementById("stage-label");
  const packet = document.getElementById("packet");
  const trail = document.getElementById("trail");
  const ping = document.getElementById("ping");
  const stamp = document.getElementById("stamp");
  const cut = document.getElementById("cut");
  const gateNote = document.getElementById("gate-note");
  const receiptNote = document.getElementById("receipt-note");
  const stageboard = document.querySelector(".stageboard");
  const chainRow = document.getElementById("chain-row");
  const media = window.matchMedia("(prefers-reduced-motion: reduce)");
  let reduce = media.matches;
  let runToken = 0;
  let seq = 0;

  // The receipt chain: each receipt, a denial included, is appended next to
  // the Receipt stage and pushes the older ones left.
  const SVG_NS = "http://www.w3.org/2000/svg";
  const CHAIN_Y = 340;
  const CHAIN_HEAD = 360;
  const CHAIN_STEP = 58;
  const CHAIN_MAX = 6;
  const chainBlocks = [];
  const layoutChain = () => {
    chainBlocks.forEach((b, i) => {
      b.style.transform = `translate(${CHAIN_HEAD - i * CHAIN_STEP}px, ${CHAIN_Y}px)`;
    });
  };
  const appendReceipt = (n, denial, animate) => {
    if (!chainRow) return;
    const g = document.createElementNS(SVG_NS, "g");
    g.setAttribute("class", `block${denial ? " deny" : ""}${animate ? " fresh" : ""}`);
    const link = document.createElementNS(SVG_NS, "path");
    link.setAttribute("d", "M23 0H35");
    link.setAttribute("class", "block-link");
    const rect = document.createElementNS(SVG_NS, "rect");
    rect.setAttribute("x", "-23"); rect.setAttribute("y", "-13");
    rect.setAttribute("width", "46"); rect.setAttribute("height", "26"); rect.setAttribute("rx", "5");
    const text = document.createElementNS(SVG_NS, "text");
    text.setAttribute("y", "3.5"); text.setAttribute("text-anchor", "middle");
    text.textContent = `#${String(n).padStart(4, "0")}`;
    g.append(link, rect, text);
    // Enter at the head position so only the older blocks slide.
    g.style.transform = `translate(${CHAIN_HEAD}px, ${CHAIN_Y}px)`;
    chainRow.append(g);
    chainBlocks.unshift(g);
    if (!animate) g.classList.add("in");
    else requestAnimationFrame(() => requestAnimationFrame(() => g.classList.add("in")));
    layoutChain();
    while (chainBlocks.length > CHAIN_MAX) {
      const old = chainBlocks.pop();
      old.classList.remove("in");
      setTimeout(() => old.remove(), 500);
    }
    setTimeout(() => g.classList.remove("fresh"), 1600);
  };
  for (let n = 1; n <= 3; n += 1) appendReceipt(n, n === 2, false);
  seq = 3;

  const GATE_IDLE = "evaluate · reserve · bind";
  const RECEIPT_IDLE = "signed · chained";

  // Paused while the board is off screen: no work nobody is watching.
  let visible = true;
  let wake = null;
  if (stageboard && "IntersectionObserver" in window) {
    new IntersectionObserver(([entry]) => {
      visible = entry.isIntersecting;
      if (visible && wake) { wake(); wake = null; }
    }).observe(stageboard);
  }
  const whenVisible = () => (visible ? Promise.resolve() : new Promise((r) => { wake = r; }));

  const delay = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
  const alive = (token) => !reduce && token === runToken;

  const setPacket = ([x, y]) => {
    if (packet) packet.setAttribute("transform", `translate(${x} ${y})`);
  };

  let trailPoints = [];
  const drawTrail = (head) => {
    if (!trail) return;
    const pts = head ? [...trailPoints, head] : trailPoints;
    trail.setAttribute("points", pts.map(([x, y]) => `${x},${y}`).join(" "));
  };

  const restart = (el, cls) => {
    if (!el) return;
    el.classList.remove(cls);
    void el.getBoundingClientRect();
    el.classList.add(cls);
  };

  const pingAt = (i) => {
    if (!ping) return;
    ping.setAttribute("cx", String(nodes[i][0]));
    ping.setAttribute("cy", String(nodes[i][1]));
    restart(ping, "go");
  };

  const setStage = (i, text) => {
    board.forEach((el, idx) => el.classList.toggle("is-on", idx === i));
    list.forEach((el, idx) => el.classList.toggle("is-on", idx === i));
    if (label) {
      label.textContent = `Stage ${String(i + 1).padStart(2, "0")} · ${text || names[i]}`;
    }
  };

  const lerp = (a, b, t) => a + (b - a) * t;

  const moveSegment = (from, to, ms, token) => new Promise((resolve) => {
    if (!packet || !alive(token)) {
      resolve();
      return;
    }
    const [x0, y0] = from;
    const [x1, y1] = to;
    const start = performance.now();
    const step = (now) => {
      if (!alive(token)) {
        resolve();
        return;
      }
      // A frame timestamp can predate `start`; unclamped, t < 0 makes the
      // smoothstep overshoot far past the segment.
      const t = Math.min(1, Math.max(0, (now - start) / ms));
      const eased = t * t * (3 - 2 * t);
      const at = [lerp(x0, x1, eased), lerp(y0, y1, eased)];
      setPacket(at);
      drawTrail(at);
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
      const len = Math.hypot(waypoints[i][0] - waypoints[i - 1][0], waypoints[i][1] - waypoints[i - 1][1]);
      lengths.push(len);
      totalLength += len;
    }
    for (let i = 1; i < waypoints.length; i += 1) {
      const ms = totalLength ? totalMs * (lengths[i - 1] / totalLength) : totalMs;
      await moveSegment(waypoints[i - 1], waypoints[i], ms, token);
      if (!alive(token)) return;
      trailPoints.push(waypoints[i]);
    }
  };

  // The gate reads its checks out one by one; a denial stops at the failure.
  const runChecks = async (deny, token) => {
    const checks = ["policy", "budget", "route"];
    const done = [];
    for (let i = 0; i < checks.length; i += 1) {
      await delay(230);
      if (!alive(token)) return;
      const failed = deny && checks[i] === "budget";
      done.push(`${checks[i]} ${failed ? "✗" : "✓"}`);
      if (gateNote) gateNote.textContent = done.join(" · ");
      if (failed) return;
    }
  };

  const resetBoard = () => {
    board.forEach((el) => el.classList.remove("is-deny", "is-dim"));
    if (stamp) stamp.classList.remove("on");
    if (cut) cut.classList.remove("on");
    if (gateNote) gateNote.textContent = GATE_IDLE;
    if (receiptNote) receiptNote.textContent = RECEIPT_IDLE;
  };

  const setReducedState = () => {
    runToken += 1;
    document.documentElement.classList.toggle("reduced", reduce);
    if (reduce) {
      resetBoard();
      setStage(2);
      setPacket(nodes[2]);
    }
  };

  const dwell = 900;
  const travel = 700;

  const runCycle = async (sequence, deny, token) => {
    await whenVisible();
    // Every await is a point where reduced motion may have taken over and
    // set its still; a stale cycle must not write over it.
    if (!alive(token)) return;
    resetBoard();
    trailPoints = [nodes[sequence[0]]];
    drawTrail();
    if (trail) trail.classList.remove("fade");
    setPacket(nodes[sequence[0]]);
    if (packet) packet.style.opacity = "1";
    setStage(sequence[0]);
    pingAt(sequence[0]);
    await delay(dwell);

    for (let i = 1; i < sequence.length; i += 1) {
      if (!alive(token)) return;
      const from = sequence[i - 1];
      const to = sequence[i];
      await moveRoute(from, to, travel, token);
      if (!alive(token)) return;
      setStage(to);
      pingAt(to);
      if (to === 2) {
        await runChecks(deny, token);
        if (!alive(token)) return;
      } else if (to === 5) {
        seq += 1;
        if (receiptNote) receiptNote.textContent = `signed · #${String(seq).padStart(4, "0")}`;
        appendReceipt(seq, false, true);
      }
      await delay(dwell);
    }
    if (!alive(token)) return;

    if (deny) {
      // Nothing crosses to the upstream. The denial is still a receipt.
      board[2].classList.add("is-deny");
      board[4].classList.add("is-dim");
      if (stamp) stamp.classList.add("on");
      if (cut) cut.classList.add("on");
      setStage(2, "Denied — budget exceeded, nothing is sent");
      await delay(1500);
      if (!alive(token)) return;
      seq += 1;
      if (receiptNote) receiptNote.textContent = `denial · #${String(seq).padStart(4, "0")}`;
      appendReceipt(seq, true, true);
      pingAt(5);
      setStage(5, "The denial is signed and chained like any receipt");
      await delay(1500);
      if (!alive(token)) return;
    }

    // Reset invisibly rather than drawing a fake Receipt -> Principal edge.
    if (trail) trail.classList.add("fade");
    if (packet) packet.style.opacity = "0";
    await delay(600);
    if (receiptNote) receiptNote.textContent = RECEIPT_IDLE;
  };

  const cycles = [
    [directSequence, false],
    [deniedSequence, true],
    [stepUpSequence, false]
  ];

  const startFlow = async () => {
    const token = ++runToken;
    let n = 0;
    while (alive(token)) {
      const [sequence, deny] = cycles[n % cycles.length];
      await runCycle(sequence, deny, token);
      n += 1;
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
