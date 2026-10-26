// Runs in the page's own JS world (document_start) so it sees behaviour before the page can hide it.
(() => {
  const send = (o) => { try { window.postMessage(Object.assign({ __td: "x" }, o), "*"); } catch (e) {} };
  const hook = (k) => send({ __td: "hook", k });
  const gesture = () => { try { return !!navigator.userActivation && navigator.userActivation.isActive; } catch (e) { return true; } };

  // web notifications
  const post = (title, opts) => send({ __td: "notif", title: String(title || ""), body: String((opts && opts.body) || "") });
  if (window.Notification) {
    window.Notification = new Proxy(window.Notification, {
      construct(target, args, newTarget) { post(args[0], args[1]); return Reflect.construct(target, args, newTarget); }
    });
  }
  const proto = window.ServiceWorkerRegistration && ServiceWorkerRegistration.prototype;
  if (proto && proto.showNotification) {
    const orig = proto.showNotification;
    proto.showNotification = function (title, opts) { post(title, opts); return orig.apply(this, arguments); };
  }

  // exit traps
  try {
    const add = EventTarget.prototype.addEventListener;
    EventTarget.prototype.addEventListener = function (type) {
      if (type === "beforeunload" && (this === window || this === document)) hook("beforeunload");
      return add.apply(this, arguments);
    };
  } catch (e) {}

  // ClickFix: page silently writes a command to the clipboard
  try {
    if (navigator.clipboard && navigator.clipboard.writeText) {
      const w = navigator.clipboard.writeText.bind(navigator.clipboard);
      navigator.clipboard.writeText = function (t) { if (!gesture()) hook("clipboard-write"); return w(t); };
    }
    const ex = Document.prototype.execCommand;
    Document.prototype.execCommand = function (c) { if (/^copy$/i.test(c) && !gesture()) hook("clipboard-write"); return ex.apply(this, arguments); };
  } catch (e) {}

  // pop-ups, forced fullscreen and drive-by downloads without a user click
  try {
    const open = window.open;
    window.open = function () { if (!gesture()) hook("popup"); return open.apply(this, arguments); };
    const rf = Element.prototype.requestFullscreen;
    if (rf) Element.prototype.requestFullscreen = function () { if (!gesture()) hook("fullscreen"); return rf.apply(this, arguments); };
    const click = HTMLAnchorElement.prototype.click;
    HTMLAnchorElement.prototype.click = function () {
      if (!gesture() && (this.hasAttribute("download") || /^blob:/.test(this.href))) hook("auto-download");
      return click.apply(this, arguments);
    };
  } catch (e) {}
})();
