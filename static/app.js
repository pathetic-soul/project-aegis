document.addEventListener("DOMContentLoaded", () => {
  const topbar = document.querySelector(".topbar");
  const menuToggle = document.querySelector(".menu-toggle");

  const setMenuOpen = (open) => {
    if (!topbar || !menuToggle) return;
    topbar.classList.toggle("is-open", open);
    menuToggle.setAttribute("aria-expanded", String(open));
    menuToggle.textContent = open ? "Close" : "Menu";
  };

  menuToggle?.addEventListener("click", () => {
    setMenuOpen(menuToggle.getAttribute("aria-expanded") !== "true");
  });

  topbar?.querySelectorAll("nav a").forEach((link) => {
    link.addEventListener("click", () => setMenuOpen(false));
  });

  document.addEventListener("keydown", (event) => {
    if (event.key === "Escape") setMenuOpen(false);
  });

  document.addEventListener("click", (event) => {
    if (topbar?.classList.contains("is-open") && !topbar.contains(event.target)) setMenuOpen(false);
  });

  window.addEventListener("resize", () => {
    if (window.innerWidth > 1060) setMenuOpen(false);
  });

  const reduceMotion = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  const revealItems = [...document.querySelectorAll("[data-reveal]")];
  if (!reduceMotion && "IntersectionObserver" in window && revealItems.length) {
    document.documentElement.classList.add("reveal-ready");
    revealItems.forEach((item, index) => item.style.setProperty("--reveal-order", String(index % 4)));
    const observer = new IntersectionObserver((entries) => {
      entries.forEach((entry) => {
        if (!entry.isIntersecting) return;
        entry.target.classList.add("is-revealed");
        observer.unobserve(entry.target);
      });
    }, { threshold: 0.14, rootMargin: "0px 0px -8% 0px" });
    revealItems.forEach((item) => observer.observe(item));
  }

  document.querySelectorAll("[data-file-control]").forEach((control) => {
    const input = control.querySelector('input[type="file"]');
    const label = control.querySelector(".file-label");
    const hint = control.querySelector("[data-file-hint]");
    const defaultLabel = label?.textContent || "Select PDF";
    const defaultHint = hint?.textContent || "PDF only";

    input?.addEventListener("change", () => {
      const file = input.files?.[0];
      control.classList.toggle("has-file", Boolean(file));
      if (label) label.textContent = file?.name || defaultLabel;
      if (hint) hint.textContent = file ? `${(file.size / 1048576).toFixed(2)} MB selected` : defaultHint;
    });
  });

  document.querySelectorAll(".evidence dd").forEach((value) => {
    if (!value.textContent?.trim()) return;
    const button = document.createElement("button");
    button.className = "copy-value";
    button.type = "button";
    button.textContent = "Copy";
    button.setAttribute("aria-label", `Copy ${value.previousElementSibling?.textContent || "evidence value"}`);
    button.addEventListener("click", async () => {
      const text = value.childNodes[0]?.textContent?.trim() || value.textContent.trim();
      try {
        await navigator.clipboard.writeText(text);
        button.textContent = "Copied";
        window.setTimeout(() => { button.textContent = "Copy"; }, 1600);
      } catch {
        button.textContent = "Select text";
      }
    });
    value.append(button);
  });

  const username = document.querySelector('input[name="username"]');
  const password = document.querySelector('input[name="password"]');
  document.querySelectorAll("[data-user]").forEach((button) => {
    button.addEventListener("click", () => {
      if (!username || !password) return;
      username.value = button.dataset.user || "";
      password.value = button.dataset.password || "";
      password.focus();
      document.querySelectorAll("[data-user]").forEach((item) => item.removeAttribute("aria-pressed"));
      button.setAttribute("aria-pressed", "true");
    });
  });
});
