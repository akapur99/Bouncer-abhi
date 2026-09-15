//
//  HeuristicSpamAnalyzer.swift
//  Bouncer
//
//  Zero-configuration spam scoring for messages that no user rule matched.
//  Pure Foundation — no IdentityLookup, no network — so it runs inside the
//  MessageFilterExtension's memory budget and is unit-testable on any
//  platform.
//
//  iOS only forwards messages from senders who are NOT in the user's
//  contacts and with whom the user has not had a real conversation, so a
//  false positive here never touches a known correspondent. Still, the
//  analyzer is deliberately conservative: verification codes and clearly
//  transactional traffic are exempt before any spam signal is scored.
//

import Foundation

struct HeuristicSpamAnalyzer {

    enum Verdict: Equatable {
        /// Not spam, or protected content (OTP / transactional).
        case allow
        /// Confident spam: score reached `junkThreshold`.
        case junk
        /// Promotional but not necessarily malicious (e.g. marketing with an
        /// opt-out footer and no scam signals).
        case promotion
    }

    struct Analysis: Equatable {
        let verdict: Verdict
        let score: Int
        let reasons: [String]
    }

    /// Score at or above which a message is junked. Individual signal weights
    /// below are calibrated so that no single weak signal can junk a message
    /// on its own, while any two independent scam signals — or one strong
    /// one plus a suspicious link — will.
    static let junkThreshold = 8

    // MARK: - Protected content

    /// Verification / one-time-passcode shapes. A missed OTP is far more
    /// costly to the user than one extra spam message, so these short-circuit
    /// to `.allow` before scoring.
    private static let otpPatterns: [NSRegularExpression] = compile([
        #"\b(?:verification|security|confirmation|authentication|access|login|one[- ]?time)\s+(?:code|pin|password|passcode)\b"#,
        #"\bOTP\b"#,
        #"\b(?:code|pin)\s*(?:is|:)\s*\d{4,8}\b"#,
        #"\b\d{4,8}\s+is\s+your\b"#,
        #"\bG-\d{6}\b"#,                          // Google
        #"\buse\s+code\s+\d{4,8}\b"#,
        #"\bcode\s+\d{4,8}\b.{0,40}\bexpires?\b"#,
        #"\bdo n[o']t share (?:this|your) code\b"#,
        #"\b2fa\b"#,
    ])

    /// Clearly transactional shapes from short codes: appointment reminders,
    /// order confirmations, fraud alerts from banks. Allowed even when they
    /// contain a link, as long as no scam-phrase signal fires.
    private static let transactionalPatterns: [NSRegularExpression] = compile([
        #"\byour (?:order|package|prescription|appointment|reservation|table|ride|driver|food|delivery) (?:is|has|will|number)\b"#,
        #"\border (?:number|no\.?|#)\s*\w+"#,
        #"\bappointment (?:on|at|with|scheduled|confirmed|reminder)\b"#,
        #"\breply (?:yes|y) to confirm\b"#,
        #"\bdid you attempt\b.{0,40}\b(?:charge|purchase|transaction)\b"#,
        #"\breply stop to (?:opt out|cancel|unsubscribe|end)\b"#,
    ])

    // MARK: - Scam phrase categories
    // Each category scores once no matter how many of its patterns match, so
    // a single verbose message can't stack the same signal repeatedly.

    private struct Category {
        let name: String
        let weight: Int
        let patterns: [NSRegularExpression]
    }

    private static let categories: [Category] = [
        Category(name: "delivery-scam", weight: 6, patterns: compile([
            #"\b(?:usps|ups|fedex|dhl|royal mail|canada post)\b.{0,80}\b(?:suspend|held|pending|unable|failed|redeliver|customs|fee|update your|address (?:is )?(?:incomplete|incorrect|invalid))\b"#,
            #"\bpackage\b.{0,60}\b(?:could ?n[o']t be delivered|delivery attempt|on hold|customs fee|address issue)\b"#,
            #"\btracking\b.{0,40}\bupdate (?:your|the) (?:address|information)\b"#,
        ])),
        Category(name: "toll-scam", weight: 6, patterns: compile([
            #"\b(?:toll|fastrak|fasttrack|e-?zpass|sunpass|txtag|ipass)\b.{0,80}\b(?:unpaid|outstanding|balance|invoice|due|violation|penalty|late fee)\b"#,
            #"\bunpaid toll\b"#,
        ])),
        Category(name: "account-phishing", weight: 6, patterns: compile([
            #"\b(?:account|apple id|icloud|netflix|amazon|paypal|venmo|zelle|bank)\b.{0,60}\b(?:suspended|locked|restricted|disabled|deactivated|on hold|unusual activity|verify (?:your|now)|confirm your identity)\b"#,
            #"\bverify your (?:account|identity|information|payment)\b"#,
            #"\byour (?:payment|card|billing) (?:method |information )?(?:was|has been|is) (?:declined|expired|suspended)\b"#,
        ])),
        Category(name: "prize-scam", weight: 6, patterns: compile([
            #"\b(?:you(?:'ve| have)? (?:won|been selected|been chosen)|congratulations?)\b.{0,60}\b(?:prize|gift|reward|winner|\$\d|free)\b"#,
            #"\bclaim your (?:prize|reward|gift|money|funds)\b"#,
            #"\bfree (?:gift|iphone|ipad|airpods|giftcard|gift card)\b"#,
        ])),
        Category(name: "money-scam", weight: 6, patterns: compile([
            #"\b(?:crypto|bitcoin|btc|usdt|forex)\b.{0,60}\b(?:profit|invest|return|earn|trading)\b"#,
            #"\bearn \$?\d[\d,]*\s*(?:per|a|\/)\s*(?:day|week|hour)\b"#,
            #"\b(?:irs|social security|ssa|tax refund)\b.{0,60}\b(?:owe|refund|suspend|legal action|lawsuit|warrant)\b"#,
            #"\bgift ?cards?\b.{0,50}\b(?:buy|purchase|send|payment)\b"#,
            #"\bwire transfer\b.{0,40}\b(?:urgent|immediately|today)\b"#,
        ])),
        Category(name: "loan-spam", weight: junkThreshold, patterns: compile([
            #"\b(?:loan|cash advance|payday|line of credit)\b.{0,60}\b(?:pre[- ]?approved|approved|qualif(?:y|ied|ies)|guaranteed|instant|fast|same[- ]day|bad credit|no credit check)\b"#,
            #"\b(?:pre[- ]?approved|approved|eligible) (?:for )?(?:a |an )?(?:\$[\d,]+|loan|cash advance|credit line)\b"#,
            #"\bborrow (?:up to )?\$[\d,]+\b"#,
            #"\b\$[\d,]+\b.{0,40}\b(?:deposited|in your account|available now)\b.{0,40}\b(?:loan|advance|funds?)\b"#,
            #"\bdebt (?:relief|forgiveness|consolidation)\b"#,
        ])),
        Category(name: "political-fundraising", weight: junkThreshold, patterns: compile([
            // Donation-platform links are the single strongest tell.
            #"\b(?:actblue|winred|secure\.anedot|ngpvan)\b"#,
            #"\b(?:donate|chip in|pitch in|give|contribute)\b.{0,60}\b(?:\$\d|before (?:the |our )?(?:midnight |fec |end[- ]of[- ](?:month|quarter) )?deadline|match(?:ed|ing)?)\b"#,
            #"\b\d+x[- ]?match(?:ed|ing)?\b"#,
            #"\b(?:democrats?|republicans?|dnc|rnc|gop|maga|trump|biden|harris|congress(?:man|woman)?|senator|campaign)\b.{0,70}\b(?:donate|chip in|contribution|fundrais|deadline|match|survey|poll|petition)\b"#,
            #"\b(?:approval|snap) poll\b"#,
            #"\bsign (?:the|our|this) petition\b"#,
        ])),
        Category(name: "job-scam", weight: 5, patterns: compile([
            #"\b(?:work from home|remote (?:job|position|work))\b.{0,60}\b(?:\$\d|per (?:day|week|hour)|flexible|no experience)\b"#,
            #"\b(?:recruiter|hiring manager|hr department)\b.{0,60}\b(?:whatsapp|telegram)\b"#,
            #"\bpart[- ]time\b.{0,50}\b\$\d{2,}\b.{0,40}\b(?:daily|per day|weekly)\b"#,
        ])),
        // The bare "is this <name>?" opener as the ENTIRE message is the
        // canonical pig-butchering opener; from an unknown sender it is
        // junked outright. The cost of a real wrong number landing in the
        // Junk folder (still delivered and readable) is acceptable.
        Category(name: "wrong-number-opener", weight: junkThreshold, patterns: compile([
            #"^\s*(?:hi|hey|hello)?[,.!\s]*(?:is this|are you)\s+\w+\s*\??\s*$"#,
        ])),
        Category(name: "wrong-number-bait", weight: 5, patterns: compile([
            #"\b(?:remember me|long time no see|it'?s been a while)\b.{0,40}\?"#,
            #"\bsorry,? wrong number\b"#,
        ])),
        Category(name: "urgency-pressure", weight: 3, patterns: compile([
            #"\b(?:act now|urgent(?:ly)?|immediate(?:ly)? required|within 24 hours|expires? (?:today|soon|tonight)|final (?:notice|warning|reminder)|last chance)\b"#,
            #"\b(?:legal action|account closure|service interruption)\b.{0,40}\bwill be\b"#,
            #"\bunless you (?:respond|reply|act|pay|verify)\b"#,
        ])),
        Category(name: "explicit-bait", weight: 6, patterns: compile([
            #"\b(?:hot|lonely|sexy) (?:girls?|singles?|women|moms?)\b"#,
            #"\b(?:hook ?up|dating) (?:tonight|near you|in your area)\b"#,
        ])),
    ]

    // MARK: - URL signals

    /// TLDs overwhelmingly used in SMS phishing campaigns and almost never in
    /// legitimate transactional traffic.
    private static let suspiciousTLDs: Set<String> = [
        "top", "xyz", "vip", "icu", "cyou", "rest", "lol", "sbs", "cfd",
        "click", "link", "live", "world", "life", "fit", "loan", "win",
        "bid", "date", "stream", "review", "faith", "racing", "party",
        "buzz", "monster", "quest", "beauty", "hair", "skin", "makeup",
        "boats", "autos", "motorcycles", "cam", "uno", "shop", "store",
    ]

    /// Brands whose names appearing inside a *non-brand* registrable domain
    /// (e.g. `usps.package-fee.top`, `secure-paypal.xyz`) are a strong
    /// phishing tell.
    private static let impersonatedBrands = [
        "usps", "fedex", "ups", "dhl", "paypal", "venmo", "zelle", "apple",
        "icloud", "amazon", "netflix", "chase", "wellsfargo", "bofa",
        "citibank", "irs", "ezpass", "fastrak", "sunpass", "coinbase",
    ]

    /// Legitimate root domains for those brands. A URL host that *ends with*
    /// one of these is fine.
    private static let legitimateBrandDomains = [
        "usps.com", "fedex.com", "ups.com", "dhl.com", "paypal.com",
        "venmo.com", "zellepay.com", "apple.com", "icloud.com",
        "amazon.com", "netflix.com", "chase.com", "wellsfargo.com",
        "bankofamerica.com", "citi.com", "irs.gov", "ezpassva.com",
        "bayareafastrak.org", "sunpass.com", "coinbase.com",
    ]

    private static let urlDetector: NSDataDetector? =
        try? NSDataDetector(types: NSTextCheckingResult.CheckingType.link.rawValue)

    // MARK: - Public API

    /// Analyze one message. `sender` is the raw sender string iOS passed to
    /// the extension (phone number, short code, or email address).
    func analyze(sender: String, body: String) -> Analysis {
        let text = body.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !text.isEmpty else { return Analysis(verdict: .allow, score: 0, reasons: []) }

        let lowered = text.lowercased()

        // 1. Protected content wins outright.
        if Self.matchesAny(Self.otpPatterns, in: lowered) {
            return Analysis(verdict: .allow, score: 0, reasons: ["otp-protected"])
        }

        var score = 0
        var reasons: [String] = []

        let isTransactional = Self.matchesAny(Self.transactionalPatterns, in: lowered)

        // 2. Scam phrase categories.
        for category in Self.categories {
            if Self.matchesAny(category.patterns, in: lowered) {
                score += category.weight
                reasons.append(category.name)
            }
        }

        // 3. URL analysis.
        let urlSignals = Self.analyzeURLs(in: text)
        score += urlSignals.score
        reasons.append(contentsOf: urlSignals.reasons)

        // 4. Sender heuristics.
        let senderSignals = Self.analyzeSender(sender)
        score += senderSignals.score
        reasons.append(contentsOf: senderSignals.reasons)

        // A transactional shape with no scam-category hit gets the benefit of
        // the doubt: URL/sender signals alone can't junk it. Any scam
        // category firing cancels the exemption — "your package could not be
        // delivered" is itself transactional-shaped.
        let scamCategoryFired = reasons.contains { name in
            Self.categories.contains { $0.name == name }
        }
        if isTransactional && !scamCategoryFired {
            return Analysis(verdict: .allow, score: score, reasons: reasons + ["transactional-exempt"])
        }

        if score >= Self.junkThreshold {
            return Analysis(verdict: .junk, score: score, reasons: reasons)
        }

        // Marketing shape: an opt-out footer plus promo language, but nothing
        // scam-flavored. Route to Promotions rather than Junk.
        if score > 0 && Self.looksPromotional(lowered) {
            return Analysis(verdict: .promotion, score: score, reasons: reasons + ["promotional"])
        }

        return Analysis(verdict: .allow, score: score, reasons: reasons)
    }

    // MARK: - URL heuristics

    private static func analyzeURLs(in text: String) -> (score: Int, reasons: [String]) {
        guard let detector = urlDetector else { return (0, []) }
        let range = NSRange(text.startIndex..., in: text)
        let matches = detector.matches(in: text, options: [], range: range)

        var score = 0
        var reasons: [String] = []
        var seen = Set<String>()

        for match in matches {
            guard let url = match.url else { continue }
            guard let host = url.host?.lowercased(), !seen.contains(host) else { continue }
            seen.insert(host)

            // IP-literal URL: no legitimate SMS sender does this.
            if host.range(of: #"^\d{1,3}(\.\d{1,3}){3}$"#, options: .regularExpression) != nil {
                score += 6
                reasons.append("url-ip-literal")
                continue
            }

            let parts = host.split(separator: ".").map(String.init)
            guard let tld = parts.last else { continue }

            if suspiciousTLDs.contains(tld) {
                score += 5
                reasons.append("url-suspicious-tld")
            }

            // Punycode — visually-spoofed domain.
            if parts.contains(where: { $0.hasPrefix("xn--") }) {
                score += 5
                reasons.append("url-punycode")
            }

            // Brand name inside a domain that isn't the brand's real domain.
            let isLegit = legitimateBrandDomains.contains { host == $0 || host.hasSuffix("." + $0) }
            if !isLegit {
                for brand in impersonatedBrands where host.contains(brand) {
                    score += 6
                    reasons.append("url-brand-impersonation")
                    break
                }
            }

            // Excessively deep subdomains hide the real domain on a phone
            // screen (`usps.com.tracking-id-8291.example.top`).
            if parts.count >= 5 {
                score += 3
                reasons.append("url-deep-subdomain")
            }
        }
        return (score, reasons)
    }

    // MARK: - Sender heuristics

    private static func analyzeSender(_ sender: String) -> (score: Int, reasons: [String]) {
        let s = sender.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        guard !s.isEmpty else { return (0, []) }

        var score = 0
        var reasons: [String] = []

        // Email-address senders are the dominant iMessage-spam vector: real
        // businesses text from short codes or 10DLC numbers, not raw inboxes.
        if s.contains("@") {
            let freeMailProviders = ["gmail.com", "outlook.com", "hotmail.com",
                                     "yahoo.com", "icloud.com", "aol.com",
                                     "proton.me", "protonmail.com", "163.com",
                                     "126.com", "qq.com", "mail.ru"]
            if freeMailProviders.contains(where: { s.hasSuffix("@" + $0) }) {
                score += 5
                reasons.append("sender-freemail")
            } else {
                score += 3
                reasons.append("sender-email")
            }
        } else {
            let digits = s.filter(\.isNumber)
            // Longer than any E.164 number — spoofed/overseas junk source.
            if digits.count > 15 {
                score += 4
                reasons.append("sender-overlong-number")
            }
        }
        return (score, reasons)
    }

    // MARK: - Promotional shape

    private static let promotionalPatterns: [NSRegularExpression] = compile([
        #"\b(?:reply|text|txt)\s+stop\b"#,
        #"\bunsubscribe\b"#,
        #"\b(?:\d{1,2}|\d{2})% off\b"#,
        #"\b(?:sale|deal|discount|coupon|promo code)\b"#,
    ])

    private static func looksPromotional(_ lowered: String) -> Bool {
        matchesAny(promotionalPatterns, in: lowered)
    }

    // MARK: - Helpers

    private static func matchesAny(_ patterns: [NSRegularExpression], in text: String) -> Bool {
        let range = NSRange(text.startIndex..., in: text)
        return patterns.contains { $0.firstMatch(in: text, options: [], range: range) != nil }
    }

    private static func compile(_ patterns: [String]) -> [NSRegularExpression] {
        patterns.compactMap {
            try? NSRegularExpression(pattern: $0, options: [.caseInsensitive])
        }
    }
}
