const TAGVEE_SW_BUILD = "CALL-FLOW-SW-2026-09-07";

self.addEventListener("install", (event) => {
    console.log(TAGVEE_SW_BUILD);
    self.skipWaiting();
});

self.addEventListener("activate", (event) => {
    event.waitUntil(self.clients.claim());
});

self.addEventListener("push", (event) => {
    let data = {};
    try {
        data = event.data ? event.data.json() : {};
    } catch (_) {
        data = { body: event.data ? event.data.text() : "Incoming TAGVEE call" };
    }

    const title = data.title || "📞 Incoming TAGVEE Call";
    const options = {
        body: data.body || "Someone wants to speak with you about your vehicle.",
        icon: "/static/images/tagvee-favicon.png",
        badge: "/static/images/tagvee-favicon.png",
        tag: "tagvee-incoming-call",
        renotify: true,
        data: { url: data.url || "/call-center" }
    };

    event.waitUntil(self.registration.showNotification(title, options));
});

self.addEventListener("notificationclick", (event) => {
    event.notification.close();
    const target = new URL(
        event.notification.data?.url || "/call-center",
        self.location.origin
    ).href;

    event.waitUntil((async () => {
        const clientsList = await self.clients.matchAll({
            type: "window",
            includeUncontrolled: true
        });

        for (const client of clientsList) {
            try {
                await client.focus();
                await client.navigate(target);
                return;
            } catch (_) {}
        }

        if (self.clients.openWindow) {
            await self.clients.openWindow(target);
        }
    })());
});
