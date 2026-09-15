//
//  SpamTesterView.swift
//  Bouncer
//
//  Paste a spam text you received, see what the filter would have done, and
//  — when the smart filter would have missed it — generate a matching Junk
//  rule on the spot. This is the self-serve feedback loop: the extension
//  can't see missed spam (iOS never shows it message history), so the user
//  brings the message to the filter instead.
//

import SwiftUI

struct SpamTesterView: View {

    /// Adds the chosen rules to the store (wired to FilterAction.import).
    let onAddRules: ([Filter]) -> Void

    /// When embedded as a lane of the rule list the chrome (nav bar, Done
    /// button, own scroll view) belongs to the host; as a sheet it's ours.
    var embedded: Bool = false

    @Environment(\.dismiss) private var dismiss
    @State private var sender = ""
    @State private var body_ = ""
    @State private var analysis: HeuristicSpamAnalyzer.Analysis?
    @State private var suggestions: [RuleSuggestion] = []
    @State private var selectedSuggestions = Set<UUID>()
    @State private var addedCount: Int?

    struct RuleSuggestion: Identifiable {
        let id = UUID()
        let phrase: String
        let type: FilterType
        let explanation: String
    }

    var body: some View {
        if embedded {
            // The Form scrolls itself; hiding its grouped background lets the
            // host stage's backdrop show through like the other lanes.
            form
                .scrollContentBackground(.hidden)
        } else {
            NavigationStack {
                form
                    .navigationTitle("TESTER_TITLE")
                    .navigationBarTitleDisplayMode(.inline)
                    .toolbar {
                        ToolbarItem(placement: .confirmationAction) {
                            Button("DONE") { dismiss() }
                        }
                    }
            }
        }
    }

    private var form: some View {
            Form {
                Section("TESTER_MESSAGE_SECTION") {
                    TextField("TESTER_SENDER_PLACEHOLDER", text: $sender)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                    TextField("TESTER_BODY_PLACEHOLDER", text: $body_, axis: .vertical)
                        .lineLimit(4...10)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                    Button("TESTER_RUN", systemImage: "wand.and.rays") {
                        runAnalysis()
                    }
                    .disabled(body_.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
                }

                if let analysis {
                    Section("TESTER_VERDICT_SECTION") {
                        verdictRow(analysis)
                        if !analysis.reasons.isEmpty {
                            Text(analysis.reasons.joined(separator: ", "))
                                .font(.caption.monospaced())
                                .foregroundStyle(.secondary)
                        }
                    }

                    if analysis.verdict != .junk && !suggestions.isEmpty {
                        Section {
                            ForEach(suggestions) { s in
                                Button {
                                    toggle(s)
                                } label: {
                                    HStack {
                                        Image(systemName: selectedSuggestions.contains(s.id)
                                              ? "checkmark.circle.fill" : "circle")
                                        VStack(alignment: .leading, spacing: 2) {
                                            Text(s.phrase).font(.body.monospaced())
                                            Text(s.explanation)
                                                .font(.caption)
                                                .foregroundStyle(.secondary)
                                        }
                                    }
                                }
                                .buttonStyle(.plain)
                            }
                            Button("TESTER_ADD_RULES", systemImage: "plus.circle.fill") {
                                addSelectedRules()
                            }
                            .disabled(selectedSuggestions.isEmpty)
                        } header: {
                            Text("TESTER_SUGGESTIONS_SECTION")
                        } footer: {
                            Text("TESTER_SUGGESTIONS_FOOTER")
                        }
                    }

                    if let addedCount {
                        Section {
                            Label(
                                String.localizedStringWithFormat(
                                    NSLocalizedString("TESTER_RULES_ADDED %lld", comment: ""),
                                    addedCount),
                                systemImage: "checkmark.seal.fill"
                            )
                            .foregroundStyle(.green)
                        }
                    }
                }
            }
    }

    @ViewBuilder
    private func verdictRow(_ analysis: HeuristicSpamAnalyzer.Analysis) -> some View {
        switch analysis.verdict {
        case .junk:
            Label("TESTER_VERDICT_JUNK", systemImage: "hand.raised.fill")
                .foregroundStyle(.red)
        case .promotion:
            Label("TESTER_VERDICT_PROMOTION", systemImage: "tag.fill")
                .foregroundStyle(.orange)
        case .allow:
            Label("TESTER_VERDICT_ALLOW", systemImage: "envelope.open.fill")
                .foregroundStyle(.green)
        }
    }

    private func runAnalysis() {
        let result = HeuristicSpamAnalyzer().analyze(sender: sender, body: body_)
        analysis = result
        addedCount = nil
        selectedSuggestions = []
        suggestions = result.verdict == .junk ? [] : Self.suggestRules(sender: sender, body: body_)
        // Preselect everything: the common case is "yes, block this".
        selectedSuggestions = Set(suggestions.map(\.id))
    }

    private func toggle(_ s: RuleSuggestion) {
        if selectedSuggestions.contains(s.id) {
            selectedSuggestions.remove(s.id)
        } else {
            selectedSuggestions.insert(s.id)
        }
    }

    private func addSelectedRules() {
        let filters = suggestions
            .filter { selectedSuggestions.contains($0.id) }
            .map { Filter(id: UUID(), phrase: $0.phrase, type: $0.type, action: .junk) }
        guard !filters.isEmpty else { return }
        onAddRules(filters)
        addedCount = filters.count
        selectedSuggestions = []
        suggestions = []
    }

    /// Candidate Junk rules for a message the smart filter didn't catch,
    /// most-specific first. Pure function for testability.
    static func suggestRules(sender: String, body: String) -> [RuleSuggestion] {
        var out: [RuleSuggestion] = []

        // 1. URL host — the strongest, most durable identifier in spam.
        if let detector = try? NSDataDetector(types: NSTextCheckingResult.CheckingType.link.rawValue) {
            let range = NSRange(body.startIndex..., in: body)
            var seen = Set<String>()
            for match in detector.matches(in: body, options: [], range: range) {
                guard let host = match.url?.host?.lowercased(), !seen.contains(host) else { continue }
                seen.insert(host)
                // Block on the registrable domain so subdomain rotation
                // (a.evil.top, b.evil.top) doesn't dodge the rule.
                let parts = host.split(separator: ".")
                let domain = parts.count >= 2 ? parts.suffix(2).joined(separator: ".") : host
                out.append(RuleSuggestion(
                    phrase: domain,
                    type: .message,
                    explanation: NSLocalizedString("TESTER_SUGGEST_DOMAIN", comment: "")))
            }
        }

        // 2. Sender — email senders are stable; phone numbers rotate, so only
        // offer the sender rule for email-style senders.
        let trimmedSender = sender.trimmingCharacters(in: .whitespacesAndNewlines)
        if trimmedSender.contains("@") {
            out.append(RuleSuggestion(
                phrase: trimmedSender.lowercased(),
                type: .sender,
                explanation: NSLocalizedString("TESTER_SUGGEST_SENDER", comment: "")))
        }

        // 3. Distinctive phrases: the longest capitalized-brand-ish or
        // money-ish token runs. Keep it simple — offer 2-4 word shingles
        // containing a $ amount or an unusual word (rare in ham).
        let normalized = HeuristicSpamAnalyzer.normalize(body)
        let words = normalized.split(separator: " ").map(String.init)
        if let moneyIdx = words.firstIndex(where: { $0.hasPrefix("$") && $0.count > 1 }) {
            let lo = max(0, moneyIdx - 1)
            let hi = min(words.count - 1, moneyIdx + 1)
            let phrase = words[lo...hi].joined(separator: " ")
            if phrase.count >= 6 {
                out.append(RuleSuggestion(
                    phrase: phrase,
                    type: .message,
                    explanation: NSLocalizedString("TESTER_SUGGEST_PHRASE", comment: "")))
            }
        }

        return out
    }
}

#Preview {
    SpamTesterView(onAddRules: { _ in })
}
