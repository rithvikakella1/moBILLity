/* A single pinned stage. Scroll advances its timeline, not a stack of sections. */
(() => {
  const reducedMotion = matchMedia('(prefers-reduced-motion: reduce)');
  const hero = document.querySelector('.hero');
  const demo = document.createElement('section');
  demo.className = 'demo-panel';
  demo.id = 'demo';
  demo.innerHTML = '<div class="demo-intro"><span class="section-tag">Clinical intelligence, in action</span><h2 class="section-title">From clinical context.<br>To clear codes.</h2><p class="section-sub">See how moBILLity turns a clinical note into ICD-10 and CPT codes, with confidence scores and suggestions for review.</p><span class="demo-caption">ILLUSTRATIVE EXTRACTION DEMO</span></div>';
  demo.append(document.querySelector('.hero-card'));
  hero.after(demo);
  document.querySelector('.scroll-cue')?.remove();

  const content = [...document.querySelectorAll('body > section, body > .stats')];
  const story = document.createElement('main');
  story.className = 'panel-story';
  story.setAttribute('aria-label', 'Explore moBILLity');
  const stage = document.createElement('div');
  stage.className = 'panel-stage';
  story.append(stage);
  hero.before(story);
  const panels = content.map((element, index) => {
    const frame = document.createElement('div');
    frame.className = 'panel-frame';
    frame.dataset.panel = String(index + 1);
    frame.append(element);
    stage.append(frame);
    return { frame, element, start: 0, overflow: 0, hold: 0, transition: 0 };
  });
  const labels = ['Introduction', 'Live demo', 'AI Calling', 'At a glance', 'How it works', 'Features', 'Compliance', 'Let’s talk'];
  const status = document.createElement('div');
  status.className = 'panel-status';
  status.innerHTML = '<span class="panel-status-label"></span><span>SCROLL TO EXPLORE ↓</span>';
  stage.append(status);
  const label = status.querySelector('.panel-status-label');
  const clamp = value => Math.max(0, Math.min(1, value));
  let layout = [], active = -1, pending = false, measuring = false;
  let stageHeight = 0;

  function update() {
    pending = false;
    const total = document.documentElement.scrollHeight - innerHeight;
    document.querySelector('.scroll-progress').style.transform = `scaleX(${total > 0 ? scrollY / total : 0})`;
    document.querySelector('body > nav').classList.toggle('scrolled', scrollY > 24);
    if (reducedMotion.matches || !layout.length) return;
    const progress = Math.max(0, -story.getBoundingClientRect().top);
    let current = layout.findIndex(panel => progress < panel.start + panel.hold + panel.transition);
    if (current < 0) current = panels.length - 1;
    const panel = layout[current];
    const local = progress - panel.start;
    const blend = current < panels.length - 1 ? clamp((local - panel.hold) / panel.transition) : 0;
    const selected = blend >= 0.5 ? current + 1 : current;
    panels.forEach((item, index) => {
      const incoming = index === current + 1 && blend > 0;
      const shown = index === current || incoming;
      const opacity = index === current ? 1 - blend : incoming ? blend : 0;
      item.frame.style.opacity = String(opacity);
      item.frame.style.visibility = shown ? 'visible' : 'hidden';
      item.frame.style.zIndex = incoming ? '2' : '1';
      item.frame.style.pointerEvents = index === selected ? 'auto' : 'none';
      item.frame.inert = index !== selected;
      item.frame.setAttribute('aria-hidden', String(index !== selected));
      // Read oversized content at full intensity during the dedicated hold.
      // It stays in place during the fade; incoming panels start at the top.
      const offset = index === current ? item.overflow * clamp(local / item.hold) : 0;
      item.element.style.transform = `translateY(${-offset}px)`;
    });
    if (selected !== active) {
      active = selected;
      label.textContent = `${String(active + 1).padStart(2, '0')} / ${String(panels.length).padStart(2, '0')}  —  ${labels[active]}`;
    }
  }
  function schedule() {
    if (!pending) { pending = true; requestAnimationFrame(update); }
  }
  function measure() {
    if (measuring) return;
    measuring = true;
    const motion = !reducedMotion.matches;
    document.documentElement.classList.toggle('pinned-panels', motion);
    if (!motion) {
      story.style.height = '';
      panels.forEach(({frame, element}) => {
        frame.removeAttribute('style');
        frame.inert = false;
        frame.removeAttribute('aria-hidden');
        element.style.transform = '';
      });
      layout = [];
      measuring = false;
      update();
      return;
    }
    const header = Math.ceil(document.querySelector('body > nav').getBoundingClientRect().height);
    story.style.setProperty('--header-height', `${header}px`);
    stageHeight = stage.clientHeight;
    panels.forEach(panel => {
      panel.overflow = Math.max(0, panel.element.scrollHeight - stageHeight + 44);
    });
    // Keep the existing fade distance and equal entry/exit rates. Each panel
    // gets a separate full-opacity interval before the next transition starts.
    const distance = Math.max(stageHeight * 1.25, ...panels.map(panel => panel.overflow * 1.1));
    let cursor = 0;
    layout = panels.map((panel, index) => {
      panel.start = cursor;
      panel.hold = Math.max(stageHeight * .55, panel.overflow);
      panel.transition = index < panels.length - 1 ? distance : 0;
      cursor += panel.hold + panel.transition;
      return panel;
    });
    story.style.height = `${cursor + stageHeight}px`;
    measuring = false;
    update();
  }
  function navigateTo(hash, behavior = 'smooth') {
    const target = document.getElementById(hash.slice(1));
    const panel = layout.find(item => item.element === target || item.element.contains(target));
    if (!panel) return false;
    const top = story.getBoundingClientRect().top + scrollY + panel.start;
    window.scrollTo({ top, behavior });
    return true;
  }
  document.addEventListener('click', event => {
    const link = event.target.closest('a[href^="#"]');
    if (!link || reducedMotion.matches || event.metaKey || event.ctrlKey || event.shiftKey || event.altKey) return;
    const hash = link.getAttribute('href');
    if (hash === '#') {
      event.preventDefault();
      window.scrollTo({ top: 0, behavior: 'smooth' });
      history.pushState(null, '', location.pathname + location.search);
    } else if (navigateTo(hash)) {
      event.preventDefault();
      history.pushState(null, '', hash);
    }
  });
  window.addEventListener('popstate', () => {
    if (location.hash) navigateTo(location.hash, 'auto');
    else window.scrollTo({ top: 0, behavior: 'auto' });
  });
  window.addEventListener('scroll', schedule, {passive: true});
  window.addEventListener('resize', measure);
  reducedMotion.addEventListener('change', measure);
  measure();
  // Recalculate for font loading, without letting the cycling demo move the timeline.
  document.fonts?.ready.then(measure);
  window.addEventListener('load', () => { measure(); if (location.hash) navigateTo(location.hash, 'auto'); });
})();
