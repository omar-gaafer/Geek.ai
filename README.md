# Geek.ai: AI Phishing & Malicious URL Detector for Banks

**CET433 – Selected Topics in Cyber · Fall 2026 · Elsewedy University of Technology (SUT)**

Geek.ai scores a URL **before the click** and estimates how likely it is to be phishing. It works from the shape of the hostname alone, so it can judge domains that no blocklist has seen yet.

[![Open In Colab](https://colab.research.google.com/assets/colab-badge.svg)](https://colab.research.google.com/github/omar-gaafer/Geek.ai/blob/main/notebooks/phase1.ipynb)

## Phase 1 results (test set, 32,853 hosts)

| Model | Precision | Recall | F1 | ROC-AUC |
|---|---|---|---|---|
| Dummy (always "legit") | – | 0.000 | 0.000 | – |
| **Logistic Regression (host-only), our baseline** | **0.875** | **0.703** | **0.780** | **0.884** |
| Logistic Regression (full URL), shortcut demo | 1.000 | 0.997 | 0.999 | 0.999 |

The full-URL model scores almost perfectly, but it is cheating. On data from outside the training set it blocks **99.9%** of legit Kaggle URLs and **15/15** real bank URLs. The host-only model blocks 22% and 7/15, and it still catches **92.7%** of fresh 2026 OpenPhish URLs.

**Why?** In PhiUSIIL every legit URL is `https://www.<domain>` with no path. A model that sees the full URL learns that pattern instead of learning what phishing looks like. See section 4.2 of the notebook and [data/README.md](data/README.md).

## Repository layout

```
├── notebooks/phase1.ipynb       # Phase 1: data → EDA → features → split → baseline → evaluation
├── src/feature_extractor.py     # URL → 12 host-only features + TLD
├── tests/                       # unit tests for the feature extractor (pytest)
├── models/baseline_logreg.joblib
├── reports/figures/             # figures used in the report and slides
├── data/README.md               # dataset sources, licences, known issues (raw data is not committed)
└── requirements.txt
```

## How to run

**Colab:** click the badge above and choose *Runtime → Run all*. Nothing needs to be uploaded. The notebook clones this repo and downloads the datasets it needs from a [public Google Drive folder](https://drive.google.com/drive/folders/1w_0md9dmjnYGvht6pmoRgVm0mA4EkI0_). If Drive is unavailable, it falls back to UCI and the live OpenPhish feed.

**Local:**
```bash
pip install -r requirements.txt
pytest -q                       # 10 tests
jupyter notebook notebooks/phase1.ipynb
```
The first notebook cell downloads any missing dataset into `data/raw/`. To get everything at once, download the whole [Drive folder](https://drive.google.com/drive/folders/1w_0md9dmjnYGvht6pmoRgVm0mA4EkI0_). See [data/README.md](data/README.md) for sources and licences.

## Method (Phase 1)

1. **Data:** PhiUSIIL (UCI #967, CC BY 4.0). The label is flipped so that `1 = phishing`, and the data is de-duplicated per hostname.
2. **Features:** 12 numeric features plus the TLD, computed from the **hostname only** after removing the scheme, `www.`, the port and the path. They cover length, labels, hyphens, digits, entropy, vowel ratio, IP and hex IP, punycode, sensitive words and free-hosting platforms.
3. **Split:** `StratifiedGroupKFold` by registered domain, 70 / 15 / 15, with `random_state=42`. Shared platforms such as `web.app` are split per site.
4. **Leakage checks:** no domain appears in more than one split, and the scaler statistics equal the training-set statistics.
5. **Model:** `Pipeline(ColumnTransformer[Imputer→Scaler | OneHot(TLD)] → LogisticRegression(class_weight="balanced"))`
6. **Metrics:** confusion matrix, precision, recall, F1, ROC-AUC and PR-AUC, plus a business-cost metric (FN = $4,500, FP = $15, triage = $2.92).

## Roadmap (Phase 2)
Random Forest and XGBoost with 5-fold CV tuning · a cost-based threshold · SHAP explanations for FP and FN cases · evasion and drift tests · a Streamlit demo.

## Ethics
This is a defensive tool built on public datasets only. Evasion techniques are used only to test the model.
