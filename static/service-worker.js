const TAGVEE_SW_BUILD = "SQA-HARDENING-SW-2026-09-25";

self.addEventListener("install", (event) => {
    console.log(TAGVEE_SW_BUILD);
    event.waitUntil(self.skipWaiting());
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

    const rawTarget = event.notification.data?.url || "/call-center";
    let target;

    try {
        const parsed = new URL(rawTarget, self.location.origin);
        // Push payloads are controlled by our server. Still reject accidental
        // cross-origin URLs so a notification can never redirect to another site.
        if (parsed.origin !== self.location.origin) {
            target = new URL("/call-center", self.location.origin).href;
        } else {
            target = parsed.href;
        }
    } catch (_) {
        target = new URL("/call-center", self.location.origin).href;
    }

    event.waitUntil((async () => {
        const clientsList = await self.clients.matchAll({
            type: "window",
            includeUncontrolled: true
        });

        // Only reuse a window that belongs to the SAME public origin.
        // This prevents a dashboard opened on the old LAN URL from hijacking
        // a push notification that arrived on the Cloudflare public origin.
        for (const client of clientsList) {
            try {
                const clientUrl = new URL(client.url);
                if (clientUrl.origin !== self.location.origin) continue;

                if ("focus" in client) await client.focus();
                if ("navigate" in client) {
                    await client.navigate(target);
                }
                return;
            } catch (_) {}
        }

        if (self.clients.openWindow) {
            await self.clients.openWindow(target);
        }
    })());
});
