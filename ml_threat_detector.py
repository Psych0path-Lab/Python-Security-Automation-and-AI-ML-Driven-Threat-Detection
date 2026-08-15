#!/usr/bin/env python3
"""ML threat detector: Random Forest (supervised) vs Isolation Forest (unsupervised)
on the UCI Phishing Websites dataset (data/phishing.csv, 11,054 samples, 30 features,
binary `result` label: -1 = phishing, 1 = legitimate).

Usage:
    python ml_threat_detector.py
"""
import pandas as pd
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report, precision_recall_fscore_support
from sklearn.model_selection import train_test_split

DATA_PATH = "data/phishing.csv"
TARGET_COL = "result"


def load_and_preprocess() -> pd.DataFrame:
    df = pd.read_csv(DATA_PATH)

    print("First 5 rows:")
    print(df.head())
    print()
    print("Class distribution (result: -1 = phishing, 1 = legitimate):")
    print(df[TARGET_COL].value_counts())
    print()

    before = len(df)
    df = df.dropna()
    after_dropna = len(df)
    print(f"Rows dropped for nulls: {before - after_dropna}")

    # All 30 features in this dataset are already integer-encoded (-1/0/1) by
    # the dataset authors, so there are no string/categorical columns left to
    # one-hot or label-encode — confirmed by checking dtypes rather than
    # assuming it.
    non_numeric = df.select_dtypes(exclude="number").columns.tolist()
    print(f"Non-numeric columns requiring encoding: {non_numeric or 'none'}")

    duplicates = df.duplicated().sum()
    df = df.drop_duplicates()
    print(f"Duplicate rows removed: {duplicates}")
    print(f"Final row count: {len(df)}")
    print()

    return df


def run_random_forest(X_train, X_test, y_train, y_test) -> dict:
    clf = RandomForestClassifier(random_state=42)  # default hyperparameters, as required
    clf.fit(X_train, y_train)
    y_pred = clf.predict(X_test)

    print("=== Random Forest — classification_report ===")
    print(classification_report(y_test, y_pred))

    precision, recall, f1, _ = precision_recall_fscore_support(y_test, y_pred, average="weighted")
    return {
        "Model": "Random Forest",
        "Accuracy": accuracy_score(y_test, y_pred),
        "Precision": precision,
        "Recall": recall,
        "F1 Score": f1,
    }


def run_isolation_forest(X_train, X_test, y_train, y_test, minority_label: int, majority_label: int) -> dict:
    contamination = (y_train == minority_label).mean()  # true minority-class proportion in training data
    iso = IsolationForest(random_state=42, contamination=contamination)
    iso.fit(X_train)  # unsupervised — never sees y_train

    # sklearn's IsolationForest.predict() returns -1 for anomalies, 1 for
    # inliers — that's a sklearn convention, not this dataset's label
    # convention, so it must be explicitly mapped onto our minority/majority
    # labels rather than assumed to line up.
    raw_pred = iso.predict(X_test)
    y_pred = pd.Series(raw_pred).map({-1: minority_label, 1: majority_label}).to_numpy()

    acc = accuracy_score(y_test, y_pred)
    precision, recall, f1, _ = precision_recall_fscore_support(
        y_test, y_pred, average="weighted", zero_division=0
    )
    print("=== Isolation Forest — anomaly detection accuracy ===")
    print(f"Accuracy: {acc:.4f}")
    print()

    return {
        "Model": "Isolation Forest",
        "Accuracy": acc,
        "Precision": precision,
        "Recall": recall,
        "F1 Score": f1,
    }


def main() -> None:
    df = load_and_preprocess()
    X = df.drop(columns=[TARGET_COL])
    y = df[TARGET_COL]

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42
    )

    counts = y.value_counts()
    minority_label = counts.idxmin()
    majority_label = counts.idxmax()
    print(f"Minority class (treated as the anomaly class for Isolation Forest): {minority_label}")
    print()

    rf_result = run_random_forest(X_train, X_test, y_train, y_test)
    iso_result = run_isolation_forest(X_train, X_test, y_train, y_test, minority_label, majority_label)

    print("=== Model comparison ===")
    comparison = pd.DataFrame([rf_result, iso_result])
    print(comparison.to_string(index=False))


if __name__ == "__main__":
    main()
