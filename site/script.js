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

  document.querySelectorAll("[data-copy]").forEach((button) => {
    const source = document.getElementById(button.dataset.copy);
    if (!source) return;
    button.addEventListener("click", async () => {
      try {
        await navigator.clipboard.writeText(source.innerText);
        button.textContent = "Copied";
        setTimeout(() => { button.textContent = "Copy"; }, 1200);
      } catch (_) {}
    });
  });

  // The film never autoplays from markup: without script it is a still
  // poster. With script it plays only when motion is welcome, and it can
  // always be paused.
  const media = window.matchMedia("(prefers-reduced-motion: reduce)");
  const film = document.getElementById("film");
  const filmToggle = document.getElementById("film-toggle");
  let filmPaused = false;
  const syncFilm = () => {
    if (!film) return;
    const run = !media.matches && !filmPaused;
    if (run) film.play().catch(() => {});
    else film.pause();
    if (filmToggle) {
      filmToggle.hidden = media.matches;
      filmToggle.setAttribute("aria-pressed", String(filmPaused));
      filmToggle.textContent = filmPaused ? "Play background" : "Pause background";
    }
  };
  if (filmToggle) filmToggle.addEventListener("click", () => { filmPaused = !filmPaused; syncFilm(); });
  media.addEventListener("change", syncFilm);
  syncFilm();

  // The demo is the recorded output of `mandate demo shop`, already in the
  // page. Motion only replays it: without script, or with reduced motion,
  // the whole transcript simply stands there.
  const demo = document.getElementById("demo");
  if (!demo) return;
  const typed = document.getElementById("demo-typed");
  const grant = demo.querySelector(".demo-grant");
  const steps = [...demo.querySelectorAll(".demo-steps li")];
  const summary = demo.querySelector(".demo-sum");
  const bar = document.getElementById("budget-bar");
  const num = document.getElementById("budget-num");
  const replay = document.getElementById("replay");
  const command = typed ? typed.textContent : "";
  const CAP = 300;
  let run = 0;

  const delay = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
  const setSpent = (eur) => {
    if (bar) bar.style.width = `${(eur / CAP) * 100}%`;
    if (num) num.textContent = `${eur} / ${CAP} EUR`;
  };
  const showAll = () => {
    run += 1;
    demo.classList.remove("playing");
    steps.forEach((li) => li.classList.remove("waiting"));
    if (typed) { typed.textContent = command; typed.classList.remove("caret"); }
    setSpent(290);
    if (replay) replay.hidden = true;
  };

  const play = async () => {
    const token = ++run;
    const alive = () => token === run;
    if (replay) replay.hidden = true;
    demo.classList.add("playing");
    [grant, summary, ...steps].forEach((el) => el && el.classList.remove("shown", "waiting"));
    setSpent(0);
    if (typed) {
      typed.textContent = "";
      typed.classList.add("caret");
      for (const ch of command) {
        await delay(55);
        if (!alive()) return;
        typed.textContent += ch;
      }
      await delay(350);
      typed.classList.remove("caret");
    }
    if (grant) grant.classList.add("shown");
    await delay(700);
    for (const li of steps) {
      if (!alive()) return;
      li.classList.add("shown");
      if (li.dataset.spent) setSpent(Number(li.dataset.spent));
      if (li.dataset.outcome === "HUMAN_REQUIRED") {
        li.classList.add("waiting");
        await delay(1900);
        if (!alive()) return;
        li.classList.remove("waiting");
      } else {
        await delay(li.classList.contains("human") ? 1400 : 950);
      }
    }
    if (!alive()) return;
    if (summary) summary.classList.add("shown");
    if (replay) replay.hidden = false;
  };

  if (replay) replay.addEventListener("click", () => { if (!media.matches) play(); });
  media.addEventListener("change", () => { if (media.matches) showAll(); });

  if (media.matches || !("IntersectionObserver" in window)) return;
  const seen = new IntersectionObserver(([entry]) => {
    if (!entry.isIntersecting) return;
    seen.disconnect();
    play();
  }, { threshold: 0.35 });
  seen.observe(demo);
})();
