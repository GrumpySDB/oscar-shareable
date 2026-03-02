(() => {
  const tabGroups = Array.from(document.querySelectorAll('[role="tablist"]')).map((tabList) => {
    const groupName = tabList.querySelector('.help-tab')?.dataset.tabGroup || '__default';
    const tabs = Array.from(tabList.querySelectorAll('.help-tab'));
    const panels = Array.from(document.querySelectorAll(`.help-tab-panel[data-tab-group="${groupName}"]`));

    return { groupName, tabs, panels };
  });

  if (!tabGroups.length) {
    return;
  }

  function activateTab(group, tabToActivate) {
    const targetId = tabToActivate.dataset.tabTarget;

    group.tabs.forEach((tab) => {
      const active = tab === tabToActivate;
      tab.classList.toggle('is-active', active);
      tab.setAttribute('aria-selected', active ? 'true' : 'false');
      tab.tabIndex = active ? 0 : -1;
    });

    group.panels.forEach((panel) => {
      const active = panel.id === targetId;
      panel.classList.toggle('is-active', active);
      panel.hidden = !active;
    });
  }

  tabGroups.forEach((group) => {
    if (!group.tabs.length || !group.panels.length) {
      return;
    }

    group.tabs.forEach((tab) => {
      tab.addEventListener('click', () => activateTab(group, tab));
      tab.addEventListener('keydown', (event) => {
        if (event.key !== 'ArrowRight' && event.key !== 'ArrowLeft') {
          return;
        }
        event.preventDefault();
        const currentIndex = group.tabs.indexOf(tab);
        const direction = event.key === 'ArrowRight' ? 1 : -1;
        const nextIndex = (currentIndex + direction + group.tabs.length) % group.tabs.length;
        const nextTab = group.tabs[nextIndex];
        nextTab.focus();
        activateTab(group, nextTab);
      });
    });
  });
})();
