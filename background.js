let winId = null;

chrome.action.onClicked.addListener(async () => {
  if (winId !== null) {
    try {
      await chrome.windows.update(winId, { focused: true });
      return;
    } catch (e) {
      winId = null;
    }
  }
  const win = await chrome.windows.create({
    url: chrome.runtime.getURL("main.html"),
    type: "popup",
    width: 1180,
    height: 780
  });
  winId = win.id;
});

chrome.windows.onRemoved.addListener((id) => {
  if (id === winId) winId = null;
});
