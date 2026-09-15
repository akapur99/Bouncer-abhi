# Bouncer — akapur99 fork with zero-config Smart Spam Filter

Fork of [afterxleep/Bouncer](https://github.com/afterxleep/Bouncer) that adds a
built-in heuristic spam analyzer, so the filter works out of the box with **no
rules to write and no maintenance** — a free, private, on-device RoboKiller
alternative.

## What this fork adds

- **`HeuristicSpamAnalyzer`** — runs inside the Message Filter extension when
  no user rule matches. Entirely on-device, no network, no subscription.
  - Scam-category scoring: delivery/USPS scams, unpaid-toll scams, account
    phishing, prize/crypto/IRS scams, job scams, wrong-number ("Hi, is this
    Jessica?") pig-butchering openers, explicit bait, urgency pressure.
  - URL analysis: suspicious TLDs (`.top`, `.xyz`, `.vip`, …), IP-literal
    links, punycode lookalikes, brand names inside non-brand domains
    (`usps-track.help-id.top`), deep subdomain cloaking.
  - Sender heuristics: freemail iMessage senders, overlong spoofed numbers.
  - **Protected content**: verification codes/OTPs and transactional messages
    (orders, appointments, bank fraud alerts) are exempted before scoring —
    they can never be junked by the analyzer.
  - Legit marketing with an opt-out footer goes to the Promotions tab, not Junk.
- Toggle in the app's ••• menu ("Smart Spam Filter", default **on**).
- User rules still take precedence: an explicit Allow rule always wins.
- Supabase analytics removed — nothing ever leaves the phone.
- Re-namespaced to `com.akapur99.bouncer` for personal signing.

Filtering only ever applies to senders **not in your contacts** — iOS never
forwards messages from known contacts to filter extensions, so friends and
family are structurally unaffected.

## One-time deploy (sideload from your Mac)

You need full **Xcode** (free, Mac App Store) — the Command Line Tools alone
can't build iOS apps.

1. `xcode-select -s /Applications/Xcode.app` (once, after installing Xcode)
2. Open `Bouncer.xcodeproj` in Xcode.
3. Select the **Bouncer** target → Signing & Capabilities → check
   "Automatically manage signing" → pick your personal team (your Apple ID).
   Repeat for the **smsfilter** target.
   - If the app-group `group.com.akapur99.bouncer` is taken, rename it in both
     targets' capabilities **and** in `FilterStoreFile.groupContainer`.
4. Plug in your iPhone, select it as the run destination, hit **Run**.
5. On the phone: **Settings → Apps → Messages → Unknown & Spam** → enable
   **Bouncer** under SMS Filtering, and turn on **Filter Unknown Senders**.

That's it. No rules needed — the smart filter is on by default. Add explicit
Allow/Junk rules in the app only if you ever want to override it.

### Signing notes

- **Free Apple ID**: build expires after 7 days, then re-run from Xcode.
- **Paid developer account ($99/yr)**: build lasts 1 year — the real
  "set-and-forget" option.
- Wireless debugging (Xcode → Devices → "Connect via network") makes re-deploys
  cable-free.

## Extending the filter

All heuristics live in
`Bouncer/Models/SMSFilter/HeuristicSpamAnalyzer.swift`. Each scam category is
a regex list plus a weight; a message is junked at score ≥ 8. Add a pattern,
rebuild, done. The analyzer is pure Foundation and testable off-device.
