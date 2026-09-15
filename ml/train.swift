// Train the SpamClassifier CoreML model from train.csv / test.csv.
// Run: swift train.swift   (requires full Xcode for the CreateML framework)

import CreateML
import CoreML
import Foundation

let dir = URL(fileURLWithPath: FileManager.default.currentDirectoryPath)

let trainTable = try MLDataTable(contentsOf: dir.appendingPathComponent("train.csv"))
let testTable = try MLDataTable(contentsOf: dir.appendingPathComponent("test.csv"))

print("Training on \(trainTable.rows.count) rows...")
let classifier = try MLTextClassifier(
    trainingData: trainTable,
    textColumn: "text",
    labelColumn: "label",
    parameters: .init(algorithm: .transferLearning(.staticEmbedding, revision: 1))
)

// Held-out evaluation
let evaluation = classifier.evaluation(on: testTable, textColumn: "text", labelColumn: "label")
print("Held-out accuracy: \(100.0 * (1.0 - evaluation.classificationError))%")

// Per-class precision/recall from the confusion matrix DataFrame
// (columns: True Label, Predicted Label, Count).
var tp = 0, fp = 0, fn = 0, tn = 0
for row in evaluation.confusion.rows {
    let actual = row["True Label"]?.stringValue ?? ""
    let predicted = row["Predicted Label"]?.stringValue ?? ""
    let count = row["Count"]?.intValue ?? 0
    switch (actual, predicted) {
    case ("spam", "spam"): tp += count
    case ("ham", "spam"): fp += count
    case ("spam", "ham"): fn += count
    case ("ham", "ham"): tn += count
    default: break
    }
}
let precision = Double(tp) / Double(max(tp + fp, 1))
let recall = Double(tp) / Double(max(tp + fn, 1))
print(String(format: "spam precision: %.4f  (false positives: %d of %d ham)", precision, fp, fp + tn))
print(String(format: "spam recall:    %.4f  (missed: %d of %d spam)", recall, fn, fn + tp))

let modelURL = dir.appendingPathComponent("SpamClassifier.mlmodel")
try classifier.write(to: modelURL, metadata: MLModelMetadata(
    author: "akapur99/Bouncer-abhi",
    shortDescription: "On-device SMS spam classifier (UCI corpus + 2026 synthetic campaigns)",
    version: "1.0"))
print("Wrote \(modelURL.path)")
