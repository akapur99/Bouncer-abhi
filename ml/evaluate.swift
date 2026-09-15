// Detailed evaluation: compile SpamClassifier.mlmodel, run every test.csv row
// through NLModel exactly as the extension will, and report the confusion
// matrix, precision/recall, and the false positives verbatim.

import CoreML
import NaturalLanguage
import Foundation

let dir = URL(fileURLWithPath: FileManager.default.currentDirectoryPath)
let compiled = try MLModel.compileModel(at: dir.appendingPathComponent("SpamClassifier.mlmodel"))
let nlModel = try NLModel(contentsOf: compiled)

let tsv = try String(contentsOf: dir.appendingPathComponent("test.tsv"), encoding: .utf8)
let rows: [(String, String)] = tsv.split(separator: "\n").compactMap { line in
    let parts = line.split(separator: "\t", maxSplits: 1, omittingEmptySubsequences: false)
    guard parts.count == 2 else { return nil }
    return (String(parts[0]), String(parts[1]))
}
var tp = 0, fp = 0, fn = 0, tn = 0
var falsePositives: [String] = []
var falseNegatives: [String] = []
var confidentSpamFP = 0  // ham predicted spam with >= 0.95 confidence

for (label, text) in rows {
    let hypotheses = nlModel.predictedLabelHypotheses(for: text, maximumCount: 2)
    let predicted = nlModel.predictedLabel(for: text) ?? "ham"
    let spamConf = hypotheses["spam"] ?? 0
    switch (label, predicted) {
    case ("spam", "spam"): tp += 1
    case ("ham", "spam"):
        fp += 1
        falsePositives.append("[\(String(format: "%.3f", spamConf))] \(text)")
        if spamConf >= 0.95 { confidentSpamFP += 1 }
    case ("spam", "ham"): fn += 1; falseNegatives.append(text)
    case ("ham", "ham"): tn += 1
    default: break
    }
}

let precision = Double(tp) / Double(max(tp + fp, 1))
let recall = Double(tp) / Double(max(tp + fn, 1))
print("test rows: \(rows.count)  tp=\(tp) fp=\(fp) fn=\(fn) tn=\(tn)")
print(String(format: "spam precision: %.4f   spam recall: %.4f", precision, recall))
print("ham misclassified as spam at >=0.95 confidence: \(confidentSpamFP)")
print("\n--- false positives (ham -> spam) ---")
falsePositives.forEach { print($0) }
print("\n--- false negatives (spam -> ham), first 10 ---")
falseNegatives.prefix(10).forEach { print($0) }
