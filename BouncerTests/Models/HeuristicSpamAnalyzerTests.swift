import XCTest
@testable import Bouncer

final class HeuristicSpamAnalyzerTests: XCTestCase {

    let analyzer = HeuristicSpamAnalyzer()

    func junk(_ sender: String, _ body: String, file: StaticString = #filePath, line: UInt = #line) {
        let a = analyzer.analyze(sender: sender, body: body)
        XCTAssertEqual(a.verdict, .junk, "expected junk, got \(a.verdict) score=\(a.score) reasons=\(a.reasons) for: \(body)", file: file, line: line)
    }

    func allow(_ sender: String, _ body: String, file: StaticString = #filePath, line: UInt = #line) {
        let a = analyzer.analyze(sender: sender, body: body)
        XCTAssertEqual(a.verdict, .allow, "expected allow, got \(a.verdict) score=\(a.score) reasons=\(a.reasons) for: \(body)", file: file, line: line)
    }

    // MARK: - Real-world spam corpus (drawn from common 2024–2026 campaigns)

    func testDeliveryScams() {
        junk("+12025550123", "USPS: Your package is on hold due to an incomplete address. Update your information at https://usps-track.help-id.top/a91")
        junk("track@delivery-us.com", "FedEx: We were unable to deliver your package. A customs fee of $1.99 is required. Pay here: http://fedex.package-fee.xyz")
        junk("+447911123456", "Your package couldn't be delivered on 09/12. Confirm your address within 24 hours: https://redeliver-usps.vip/x")
    }

    func testTollScams() {
        junk("+18885550111", "FasTrak: You have an unpaid toll balance of $6.87. To avoid a late fee of $50, pay now at https://fastrak-pay.cyou")
        junk("ezpass@notice.com", "E-ZPass Final Notice: outstanding toll invoice. Legal action will be filed. https://ezpass.com-billing.icu/pay")
    }

    func testAccountPhishing() {
        junk("+13105550188", "Apple: Your Apple ID has been suspended due to unusual activity. Verify now: https://appleid-verify.sbs/login")
        junk("alerts@secure-chase.top", "Chase Bank: Your account is locked. Confirm your identity at https://chase-secure.top immediately.")
        junk("+15555550100", "Netflix: your payment was declined. Update your billing information within 24 hours or your account will be deactivated: http://netflix-billing.icu")
    }

    func testPrizeAndMoneyScams() {
        junk("+19495550122", "Congratulations! You've been selected to receive a FREE iPhone 17. Claim your prize: https://prize-usa.win/claim")
        junk("crypto100@gmail.com", "Earn $500 per day trading bitcoin with our expert team! No experience needed. Join: https://btc-profit.vip")
        junk("+12125550177", "IRS Notice: You owe back taxes. Legal action and a warrant will be issued unless you respond immediately.")
    }

    func testJobScams() {
        junk("hr.recruiter88@gmail.com", "Hello! I'm a hiring manager. We offer flexible remote work, $300-800 per day. Contact me on WhatsApp to start.")
    }

    func testWrongNumberBait() {
        junk("+16465550110", "Hi, is this Jessica?")
        // Bait openers ride on a freemail sender to cross the threshold.
        junk("lonelygirl2@hotmail.com", "Hey, it's been a while! Remember me?")
    }

    func testExplicitBait() {
        junk("dating4u@163.com", "Hot singles near you are waiting to hook up tonight! https://meet-now.date/go")
    }

    // MARK: - Ham: must never be junked

    func testOTPProtected() {
        allow("287-87", "Your verification code is 482913. Do not share this code.")
        allow("+12065550000", "G-583920 is your Google verification code.")
        allow("764-53", "Use code 9921 to log in. It expires in 10 minutes.")
        allow("Apple", "Your Apple ID Code is: 613842. Don't share it with anyone.")
    }

    func testTransactionalAllowed() {
        allow("828-28", "Your order number 1Z999AA1 has shipped. Track it in the app.")
        allow("+18005551234", "Reminder: your appointment with Dr. Patel is scheduled for Monday at 2 PM. Reply YES to confirm.")
        allow("CHASE", "Chase: Did you attempt a charge of $43.12 at SHELL? Reply YES or NO.")
        allow("555-55", "Your table for 2 at Nopa is confirmed for 7:30 PM tonight.")
        allow("+14155550123", "Your Uber driver Miguel is arriving in a white Camry, plate 8ABC123.")
    }

    func testOrdinaryConversation() {
        allow("+14155550999", "Hey, are we still on for dinner tomorrow?")
        allow("+13235550101", "Running 10 min late, sorry!")
        allow("+16505550111", "Can you send me the address for Saturday?")
        allow("+12025550142", "Thanks so much for yesterday. The kids had a blast.")
        allow("+19175550123", "Your dad and I will land at 3pm. See you at baggage claim.")
    }

    func testLegitimateMarketingIsPromotionNotJunk() {
        let a = analyzer.analyze(sender: "26787", body: "SEPHORA: 20% off everything this weekend! Shop now. Reply STOP to opt out.")
        XCTAssertNotEqual(a.verdict, .junk, "legit marketing must not be junked, reasons=\(a.reasons)")
    }

    func testLegitimateBrandDomainNotFlagged() {
        allow("+18005551111", "USPS: Your package will arrive Tuesday. Track at https://tools.usps.com/go/Track")
    }

    // MARK: - URL heuristics

    func testIPLiteralURL() {
        let a = analyzer.analyze(sender: "+15555550101", body: "check this out http://45.83.12.9/win")
        XCTAssertTrue(a.reasons.contains("url-ip-literal"), "reasons=\(a.reasons)")
    }

    func testBrandImpersonationDomain() {
        let a = analyzer.analyze(sender: "+15555550102", body: "visit https://secure-paypal-refund.com/claim now")
        XCTAssertTrue(a.reasons.contains("url-brand-impersonation"), "reasons=\(a.reasons)")
    }

    func testEmptyAndNilSafety() {
        allow("", "")
        allow("+15555550103", "   ")
    }

    // MARK: - Loan spam ("Cynthia" wrong-name loan offers)

    func testLoanSpam() {
        junk("+18325550147", "Cynthia, your $2,500 loan is pre-approved! Funds can be deposited today. Claim now: https://fastcash-now.top/c")
        junk("+19095550172", "Hi Cynthia! You qualify for a same-day cash advance up to $5,000. No credit check needed.")
        junk("loans4u@gmail.com", "Bad credit OK! You are approved for a payday loan. Borrow up to $1,000 instantly.")
        junk("+15125550118", "Final notice for Cynthia: your debt relief program enrollment expires today. Act now.")
    }

    func testLegitimateLoanTrafficAllowed() {
        allow("CHASE", "Chase: Your loan payment of $312.44 was received. Thank you.")
        allow("+18005559999", "Your mortgage statement is ready. Log in to your account to view it.")
    }

    // MARK: - Political fundraising spam (party-agnostic)

    func testPoliticalFundraisingSpam() {
        junk("+12025550190", "It's official: Democrats need YOU. Chip in $15 before our midnight FEC deadline and your gift is 4X-MATCHED! https://secure.actblue.com/d/xyz")
        junk("+16155550183", "President Trump needs your answer! Take this approval poll and your donation will be 5x matched. Donate via WinRed now.")
        junk("+13135550166", "URGENT: The GOP is counting on patriots like you. Pitch in $25 before the end-of-month deadline!")
        junk("+17185550155", "Sign our petition to stop the radical agenda in Congress. Add your name now!")
    }

    func testCivicMessagesAllowed() {
        allow("+13605550122", "Reminder: tomorrow is Election Day. Your polling place is Lincoln Elementary, open 7am-8pm.")
        allow("+14085550133", "Hey it's Sam. Are you coming to the campaign volunteer meeting tonight?")
    }

    // MARK: - Obfuscation resistance (normalization pre-pass)

    func testZeroWidthCharacterEvasion() {
        junk("+15555550171", "Your l\u{200B}oan is pre-app\u{200B}roved! No credit check. Claim $2,500 now")
    }

    func testLeetspeakEvasion() {
        junk("+15555550172", "Cynthia your L0an is appr0ved! N0 credit check needed. Borrow up to $5,000")
    }

    func testHomoglyphEvasion() {
        junk("+15555550173", "Your p\u{0430}ckage could not be delivered. Update your \u{0430}ddress within 24 hours")
        junk("+15555550174", "\u{FF23}ongratulations! You have been selected to receive a free gift card prize")
    }

    func testNormalizationDoesNotBreakHam() {
        allow("287-87", "Your verification code is 482913. Do not share this code.")
        allow("+14155550999", "Hey! Dinner at 7 still? Save $10 if we do happy hour lol")
    }

    // MARK: - Rule suggestion (spam tester)

    func testSuggestsRegistrableDomainAndEmailSender() {
        let suggestions = SpamTesterView.suggestRules(
            sender: "spammer@shady.biz",
            body: "New offer just for you: https://promo.weird-deals.example/win")
        XCTAssertTrue(suggestions.contains { $0.phrase == "weird-deals.example" && $0.type == .message })
        XCTAssertTrue(suggestions.contains { $0.phrase == "spammer@shady.biz" && $0.type == .sender })
    }

    func testDoesNotSuggestPhoneSenderRule() {
        let suggestions = SpamTesterView.suggestRules(sender: "+15551234567", body: "plain message no url")
        XCTAssertFalse(suggestions.contains { $0.type == .sender })
    }
}
