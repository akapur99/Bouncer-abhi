//
//  MessageFilterEngine.swift
//  Bouncer
//
//  Outcome-decision logic for the SMS Message Filter extension, lifted out
//  of MessageFilterExtension so it can be unit-tested without the
//  IdentityLookup runtime. The extension's handle(_:context:completion:) is
//  the wiring around this; the engine is what makes the verdict.
//

import Foundation
import IdentityLookup

struct MessageFilterEngine {

    let filters: [Filter]

    /// When true and no user rule matched, the built-in HeuristicSpamAnalyzer
    /// scores the message. User rules always take precedence — an explicit
    /// allow rule short-circuits before the analyzer ever runs.
    var useSmartFilter: Bool = true

    func decide(sender: String?, messageBody: String?) -> (response: ILMessageFilterQueryResponse, matched: Filter?) {
        let response = ILMessageFilterQueryResponse()
        guard let sender = sender, let messageBody = messageBody else {
            response.action = .none
            response.subAction = .none
            return (response, nil)
        }
        let engine = SMSOfflineFilter(filterList: filters)
        let message = SMSMessage(sender: sender, text: messageBody)
        guard let matched = engine.matchingFilter(message: message) else {
            if useSmartFilter {
                let analysis = HeuristicSpamAnalyzer().analyze(sender: sender, body: messageBody)
                switch analysis.verdict {
                case .junk:
                    response.action = .junk
                    response.subAction = .none
                    return (response, nil)
                case .promotion:
                    response.action = .promotion
                    response.subAction = .promotionalOthers
                    return (response, nil)
                case .allow:
                    break
                }
            }
            response.action = .none
            response.subAction = .none
            return (response, nil)
        }
        response.action = engine.action(for: matched)
        response.subAction = engine.subAction(for: matched)
        return (response, matched)
    }
}
