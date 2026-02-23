(() => {
  const tabs = Array.from(document.querySelectorAll('.help-tab'));
  const panels = Array.from(document.querySelectorAll('.help-tab-panel'));

  if (!tabs.length || !panels.length) {
    return;
  }

  function activateTab(tabToActivate) {
    const targetId = tabToActivate.dataset.tabTarget;

    tabs.forEach((tab) => {
      const active = tab === tabToActivate;
      tab.classList.toggle('is-active', active);
      tab.setAttribute('aria-selected', active ? 'true' : 'false');
      tab.tabIndex = active ? 0 : -1;
    });

    panels.forEach((panel) => {
      const active = panel.id === targetId;
      panel.classList.toggle('is-active', active);
      panel.hidden = !active;
    });
  }

  tabs.forEach((tab) => {
    tab.addEventListener('click', () => activateTab(tab));
    tab.addEventListener('keydown', (event) => {
      if (event.key !== 'ArrowRight' && event.key !== 'ArrowLeft') {
        return;
      }
      event.preventDefault();
      const currentIndex = tabs.indexOf(tab);
      const direction = event.key === 'ArrowRight' ? 1 : -1;
      const nextIndex = (currentIndex + direction + tabs.length) % tabs.length;
      const nextTab = tabs[nextIndex];
      nextTab.focus();
      activateTab(nextTab);
    });
  });
})();
