# AI-Driven Phishing and Malicious URL Detection System for Financial Institutions

> **Course:** CET433 – Selected Topics in Cyber (Fall 2026)  
> **Department:** Department of Computer Science Technology – Network and Cybersecurity Technology Program  
> **Institution:** Elsewedy University of Technology (SUT) – Polytechnic of Egypt  
> **Instructors:** Dr. Mariam Labib, Eng. Maryam Adel  
> **Project Title:** Project 1: AI Phishing and Malicious URL Detector for Banks  
> **Team Composition:** 3–4 Students  
> **Total Evaluation:** 20 Marks (Phase 1: 8 Marks | Phase 2: 12 Marks)  

---

## Table of Contents
1. [Project Overview & Executive Summary](#1-project-overview--executive-summary)
2. [Market Need & Threat Landscape](#2-market-need--threat-landscape)
3. [Target Customer & Stakeholder Persona](#3-target-customer--stakeholder-persona)
4. [System Architecture & End-to-End Pipeline](#4-system-architecture--end-to-end-pipeline)
5. [Feature Engineering & Data Strategy](#5-feature-engineering--data-strategy)
6. [Machine Learning Modeling & Methodology](#6-machine-learning-modeling--methodology)
7. [Explainability (XAI) & Adversarial Robustness](#7-explainability-xai--adversarial-robustness)
8. [Performance & Business Metrics](#8-performance--business-metrics)
9. [Detailed Project Phases & Marking Scheme](#9-detailed-project-phases--marking-scheme)
10. [Work Breakdown Structure (WBS) & Actionable Tasks](#10-work-breakdown-structure-wbs--actionable-tasks)
11. [Team Role Distribution & Git Strategy](#11-team-role-distribution--git-strategy)
12. [Deliverables & Submission Guidelines](#12-deliverables--submission-guidelines)
13. [Ethical Considerations & Rulebook Compliance](#13-ethical-considerations--rulebook-compliance)

---

## 1. Project Overview & Executive Summary

The **AI Phishing and Malicious URL Detector for Banks** is an intelligent security solution engineered to intercept and classify zero-hour malicious and phishing hyperlinks before users interact with them. 

Traditional perimeter defenses, such as static blocklists and reputation feeds (e.g., DNS blocklists, Google Safe Browsing, Spamhaus), operate **reactively**—a domain or URL is only blacklisted *after* victims have already fallen prey or analysts have verified malicious activity. In financial contexts, threat actors leverage fast-flux infrastructure, disposable dynamic DNS domains, and targeted credential-harvesting kits that stay active for mere hours, bypassing static databases entirely.

This project designs, trains, evaluates, and deploys an automated machine learning and explainable AI (XAI) pipeline that inspects structural, lexical, domain, and statistical properties of URLs. Implemented in Python using Scikit-Learn, Pandas, XGBoost/LightGBM, and SHAP, the system delivers real-time risk scores, pinpoints deceptive indicators, and withstands adversarial evasion attacks.

```
+----------------------------------------------------------------------------------------------------+
|                                    High-Level Conceptual Flow                                     |
|                                                                                                    |
|  [ Inbound URL / Email Link ]                                                                      |
|             │                                                                                      |
|             ▼                                                                                      |
|  [ Feature Extraction Engine ] ──► (Length, Entropy, Suspicious Tokens, Domain Age, TLD, Punycode) |
|             │                                                                                      |
|             ▼                                                                                      |
|  [ Leak-Free ML Pipeline ]    ──► (StandardScaler / Imputer / Class Balancing)                     |
|             │                                                                                      |
|             ▼                                                                                      |
|  [ Tuned Ensemble Classifier] ──► (Random Forest / LightGBM / XGBoost)                             |
|             │                                                                                      |
|             ▼                                                                                      |
|  [ Calibrated Risk Verdict ]  ──► P(Malicious) >= Threshold (Optimized for Low False Positives)   |
|             │                                                                                      |
|             ▼                                                                                      |
|  [ XAI & Decision Engine ]    ──► SHAP Attribution (Why was this flagged?) + SOC Action Alert      |
+----------------------------------------------------------------------------------------------------+
```

---

## 2. Market Need & Threat Landscape

### 2.1 The Cybersecurity Problem
Phishing remains the primary initial attack vector responsible for over 80% of reported security incidents and billions of dollars in annual fraud losses across the financial sector:
* **Credential Harvesting:** Fraudulent clones of retail banking portals capture online banking credentials, one-time passwords (OTPs), and credit card details.
* **Ephemeral Infrastructure:** Attackers create short-lived domains registered on low-cost TLDs (`.xyz`, `.top`, `.buzz`) or utilize hijacked subdomains on legitimate cloud hosting platforms (e.g., Firebase, Azure Blob Storage, GitHub Pages).
* **Latency of Blocklists:** Industry studies demonstrate that static blocklists require 6 to 48 hours to list a freshly registered malicious URL. Over 65% of phishing victims engage with fraudulent links within the first 60 minutes of the campaign launch.

### 2.2 Why Machine Learning Solves This
Machine Learning models analyze the inherent **syntactic, morphological, and structural patterns** of URLs independently of centralized blacklist checks:
1. **Pre-Click Scoring:** Evaluates arbitrary, unseen URLs instantly at the point of arrival (gateway) or point of click (client browser).
2. **Generalization:** Detects novel lexical obfuscation patterns, typosquatting techniques, and suspicious token combinations that match past adversary tradecraft.
3. **Operational Cost Reduction:** Automates tier-1 SOC alert triage, reducing manual URL investigation workload by thousands of analyst-hours annually.

---

## 3. Target Customer & Stakeholder Persona

The system is designed for commercial deployment within financial and cyber-defense architectures:

| Stakeholder Category | Role / Persona | Operational Pain Point | Business Value Delivered |
| :--- | :--- | :--- | :--- |
| **Primary Customer** | Retail Bank Security Operations Center (SOC) / Fraud Team | Flooded with customer reports of suspicious SMS/email links; high rate of financial fraud write-offs. | Real-time URL threat scoring, automated quarantine of customer-reported links, and reduced fraud losses. |
| **Secondary Customer** | Enterprise Secure Email Gateway (SEG) Vendor | Inability to inspect weaponized links with zero prior threat history in real time. | Low-latency inference API integrated into mail-flow pipelines to rewrite and block suspicious links. |
| **Tertiary Customer** | Browser Extension Vendor / E-Banking Portal Developers | End-users accessing banking services via mobile or unmanaged desktop browsers without endpoint protection. | Client-side or proxy-assisted browser extension alerting users before page navigation occurs. |

---

## 4. System Architecture & End-to-End Pipeline

The project lifecycle spans two structured phases progressing from data engineering and baseline prototyping to an enterprise-grade defense platform.

```
========================================================================================================
                                 END-TO-END PIPELINE DIAGRAM
========================================================================================================

   PHASE 1: Proposal & Baseline (8 Marks)
   ───────────────────────────────────────
   ┌───────────────────────┐      ┌─────────────────────────┐      ┌─────────────────────────┐
   │ 1. URL Collection     │      │ 2. Feature Extraction   │      │ 3. Baseline Model       │
   │ - PhishTank (Mal)     │ ───► │ - Lexical & Symbols     │ ───► │ - Leak-Free Pipeline    │
   │ - OpenPhish (Mal)     │      │ - Entropy & Domain Age  │      │ - Logistic Regression   │
   │ - Tranco / Benign     │      │ - Temporal/Strata Split │      │ - Confusion Matrix & F1 │
   └───────────────────────┘      └─────────────────────────┘      └─────────────────────────┘
                                                                                │
   ─────────────────────────────────────────────────────────────────────────────┼──────────────────────
                                                                                ▼
   PHASE 2: Final System & Defense (12 Marks)
   ──────────────────────────────────────────
   ┌───────────────────────┐      ┌─────────────────────────┐      ┌─────────────────────────┐
   │ 4. Ensemble Tuning    │      │ 5. Explainability &     │      │ 6. Interactive Prototype│
   │ - Random Forest       │      │    Adversarial Defense  │      │    & Business Defense   │
   │ - XGBoost / LightGBM  │ ───► │ - SHAP Force/Summary    │ ───► │ - Streamlit / Flask UI  │
   │ - 5-Fold Stratified CV│      │ - Obfuscation & Evasion │      │ - Cost-Benefit Analysis │
   │ - Precision-Recall Opt│      │ - Threshold Calibration │      │ - 10-15 Page Report     │
   └───────────────────────┘      └─────────────────────────┘      └─────────────────────────┘
========================================================================================================
```

---

## 5. Feature Engineering & Data Strategy

### 5.1 Permissible Data Sources
To comply with academic rules, all datasets must be publicly available or anonymized, fully cited, and documented:
* **Malicious Sources:**
  * **PhishTank:** Verified active phishing URL feed ([phishtank.org](https://phishtank.org/developer_info.php)).
  * **OpenPhish:** Global feed of verified active phishing links ([openphish.com](https://openphish.com)).
  * **ISCX-URL2016:** University of New Brunswick benchmark dataset featuring labeled benign, phishing, malware, and defacement URLs.
* **Benign Sources:**
  * **Tranco Top 1M / Majestic Million:** Top-ranked legitimate domains to model benign internet traffic and avoid false positives.
  * **University / Corporate Web Lists:** Validated benign subdomains and deep links.

### 5.2 Feature Extraction Specification
Raw URLs are transformed into engineered tabular feature vectors across four primary feature domains:

```
+--------------------------------------------------------------------------------------------------+
|                                    URL FEATURE TAXONOMY                                         |
+------------------------------------+-------------------------------------------------------------+
| Category                           | Extracted Attributes & Rationale                            |
+------------------------------------+-------------------------------------------------------------+
| 1. Lexical & Structural Metrics    | * Total URL Length, Path Length, Query Length               |
|                                    | * Number of Dots ('.'), Hyphens ('-'), Underscores ('_')    |
|                                    | * Count of Suspicious Characters ('@', '//', '%', '=', '?')|
|                                    | * Count of Subdomains (excessive subdomains denote evasion) |
|                                    | * IP Address Presence (Direct IP used instead of Domain)    |
|                                    | * Hex / Octal Obfuscated Octets (e.g., '0x7f.0.0.1')        |
+------------------------------------+-------------------------------------------------------------+
| 2. Statistical & Information Theory| * Shannon Entropy of URL String and Domain Name             |
|                                    | * Vowel-to-Consonant Ratio (identifies DGA generation)      |
|                                    | * Ratio of Numeric Characters to Alphabetical Characters    |
|                                    | * Consecutive Character Sequences / Repeating Bigrams       |
+------------------------------------+-------------------------------------------------------------+
| 3. Domain & Host Attributes        | * Top-Level Domain (TLD) Reputation (.bank vs .xyz, .top)   |
|                                    | * Punycode / IDN Homograph Presence (e.g., 'xn--')         |
|                                    | * Presence of Sensitive Security Keywords in Host/Path      |
|                                    |   ('login', 'verify', 'update', 'banking', 'secure', 'otp') |
|                                    | * Domain Registration Age & Expiry Time (WHOIS metadata)    |
+------------------------------------+-------------------------------------------------------------+
| 4. Content / Stretch Features      | * HTTP Status Code & Redirect Chain Count (if safe)         |
|                                    | * TF-IDF representation of path tokens                      |
|                                    | * (Stretch) Associated email body text tokens               |
+------------------------------------+-------------------------------------------------------------+
```

---

## 6. Machine Learning Modeling & Methodology

### 6.1 Data Splitting & Leakage Prevention Rules
* **Strict Order of Operations:** Data must be split into Training (70%), Validation (15%), and Test (15%) subsets **before** any feature scaling, imputing, or vectorizer fitting occurs.
* **Temporal / Stratified Splitting:** Where timestamps are available, time-based splits are used to mirror production deployment (train on past, test on future). Otherwise, Stratified K-Fold cross-validation preserves target distribution.
* **Pipeline Encapsulation:** All transformations are wrapped inside `sklearn.pipeline.Pipeline` objects to eliminate data leakage.
* **Fixed Random Seed:** `random_state=42` must be declared across all splitters and estimators for deterministic reproducibility.

### 6.2 Model Progression Hierarchy
1. **Phase 1 Baseline:**
   * **Logistic Regression:** Serves as a transparent linear benchmark.
   * **Alternative Baseline:** Gaussian Naive Bayes or Decision Tree (depth-constrained).
2. **Phase 2 Advanced Ensembles:**
   * **Random Forest Classifier:** Bagging ensemble robust to noisy tabular features and non-linear interactions.
   * **Gradient Boosting (XGBoost / LightGBM):** Sequentially boosted decision trees optimized for class-imbalanced tabular datasets.
   * **Optional Deep Learning Benchmark (Stretch):** 1D Character-Level Convolutional Neural Network (Char-CNN) consuming raw URL string sequences.

---

## 7. Explainability (XAI) & Adversarial Robustness

### 7.1 Explainable AI with SHAP & LIME
In banking applications, a "black box" model is unacceptable. Security analysts must understand *why* an alert was triggered:
* **Global Interpretability:** TreeExplainer summary plots identifying top contributing features across the entire population.
* **Local Interpretability:** Individual force plots and waterfall plots computed for:
  * **True Positives (TP):** Verifying model relies on genuine phishing markers rather than coincidental dataset artifacts.
  * **False Positives (FP):** Analyzing why a benign banking link was incorrectly blocked, revealing over-sensitive features.
  * **False Negatives (FN):** Investigating how an evasive phishing URL slipped through detection.

### 7.2 Adversarial Robustness & Evasion Testing
Attackers continuously adapt their tactics. The system must undergo simulated adversarial stress-testing:
1. **URL Padding & Lengthening:** Appending benign keywords (`?client=microsoft&auth=success`) to artificially lower threat entropy.
2. **Hyphenation & Delimiter Inflation:** Inserting dashes into brand names (`chase-bank-verify-security.com`).
3. **Subdomain Hopping / Deep Stacking:** Embedding the target bank name as a third-level subdomain on a free host (`chase.com.accounts-secure-portal.xyz`).
4. **IP Encoding & Hex Transformation:** Converting IP addresses to decimal, hex, or octal representations.
5. **Data Drift Simulation:** Evaluating performance degradation when evaluated against newly registered phishing campaigns appearing months after the training distribution.

---

## 8. Performance & Business Metrics

### 8.1 Technical Metrics
Standard accuracy is misleading in cyber-defense due to severe class imbalance (benign URLs vastly outnumber phishing URLs in real environments). The project evaluates:
* **Confusion Matrix:** Breakdown of TP, FP, TN, and FN.
* **Precision ($\frac{TP}{TP + FP}$):** Critical to avoid blocking legitimate bank customers.
* **Recall / True Positive Rate ($\frac{TP}{TP + FN}$):** Critical to catch malicious campaigns before exposure.
* **F1-Score / $F_{\beta}$-Score:** Harmonic mean balancing detection versus alarm noise ($F_{0.5}$ prioritizes precision; $F_2$ prioritizes recall).
* **PR-AUC & ROC-AUC:** Area under curves across varying probability thresholds.

### 8.2 Domain-Specific Business Metric: "Cost of Security Operation"
The model decision threshold is optimized not for an arbitrary 0.5 probability, but against a quantified financial loss matrix:

$$\text{Total Expected Cost} = (FN \times \text{Cost}_{\text{Breach}}) + (FP \times \text{Cost}_{\text{Interruption}}) + (\text{Alerts} \times \text{Cost}_{\text{Triage}})$$

* **Assumptions:**
  * Average fraud loss per successful credential-harvesting phishing attack: **\$4,500**.
  * Operational cost of investigating a False Positive (customer blocked + tier-1 support ticket): **\$15**.
  * Analyst time to triage a flagged URL alert: **5 minutes** (\$35/hour equivalent).
* **Target Objective:** Tune the classification cutoff threshold to minimize Total Cost, ensuring False Positive Rate is constrained under **0.5%** while maintaining Recall **> 95%**.

---

## 9. Detailed Project Phases & Marking Scheme

The 20 marks are apportioned into two milestone phases:

| Phase | Evaluation Criterion | Marks | Required Deliverables & Success Criteria |
| :---: | :--- | :---: | :--- |
| **Phase 1** | **Problem and Market Case** | **2.0** | Clearly defined customer (bank SOC, SEG, extension), threat impact analysis, justification of AI superiority over static blocklists, upfront technical and business success metrics. |
| **Phase 1** | **Data and Preprocessing Pipeline** | **3.0** | Dataset provenance and licensing documentation; EDA plots; cleaning, encoding, and scaling; strict pre-split execution; class imbalance mitigation; documented zero-leakage check. |
| **Phase 1** | **Baseline Model and Metrics** | **3.0** | Working scikit-learn baseline pipeline (e.g., Logistic Regression); confusion matrix; precision, recall, F1-score; technical justification of chosen evaluation criteria. |
| **Phase 2** | **Final Models and Improvement** | **4.0** | Implementation of $\ge 3$ algorithms (Baseline, Random Forest, XGBoost/LightGBM, optional Char-CNN); cross-validated hyperparameter tuning on training data; proven performance gains. |
| **Phase 2** | **Evaluation, Explainability & Robustness** | **3.0** | Threshold calibration mapped to business cost; SHAP or LIME force plots for $\ge 1$ False Negative and $\ge 1$ False Positive; formal adversarial evasion test (obfuscation/padding). |
| **Phase 2** | **Working Prototype / Demo** | **2.0** | Interactive web application (Streamlit or Flask) accepting arbitrary input URLs, extracting features, and outputting risk scores, verdicts, and feature explanations in real-time. |
| **Phase 2** | **Report and Business Case** | **1.5** | Rigorous 10–15 page technical report; system architecture diagrams; deployment and maintenance constraints; ethical impact statement and dual-use policy. |
| **Phase 2** | **Oral Defense & Individual Contribution** | **1.5** | 10-minute presentation per phase; individual mastery demonstrated during faculty Q&A; Git commit history verified against individual responsibilities. |
| **TOTAL** | **Comprehensive Evaluation** | **20.0** | **Phase 1 Total: 8 Marks \| Phase 2 Total: 12 Marks** |

---

## 10. Work Breakdown Structure (WBS) & Actionable Tasks

### 10.1 Phase 1 Breakdown: Proposal & Baseline (Weeks 1 – 4)

#### Task 1.1: Market Case, Customer Persona & Problem Definition
* **Deliverable:** Section 1 of Project Proposal & Phase 1 Presentation Deck.
* **Step-by-Step Actions:**
  1. Profile the target end-user (e.g., Retail Bank Cyber Defense Center).
  2. Document the threat landscape: financial impact of credential theft and phishing kits.
  3. Formulate the value proposition of machine learning versus DNS/URL blocklists.
  4. Specify quantitative acceptance targets (e.g., Target $F_1 \ge 0.92$, $FPR \le 0.5\%$).

#### Task 1.2: Dataset Acquisition, Licensing & Exploratory Data Analysis (EDA)
* **Deliverable:** Colab Notebook Section: Data Ingestion & EDA.
* **Step-by-Step Actions:**
  1. Download and verify accessibility of PhishTank, OpenPhish, and Tranco/ISCX datasets.
  2. Document dataset licenses, collection timestamps, and sample volume (e.g., 50k benign, 50k phishing).
  3. Perform EDA: analyze URL length distributions, character distributions, domain suffixes, and missing values.
  4. Generate exploratory visualizations: class distribution bar charts, correlation heatmaps, box plots.

#### Task 1.3: Feature Engineering Engine Implementation
* **Deliverable:** Modular Python script (`feature_extractor.py`) in repository.
* **Step-by-Step Actions:**
  1. Implement lexical extractors: total length, hostname length, path depth, count of dots, slashes, hyphens, `@`, `?`, `%`, `=`.
  2. Implement information-theoretic extractors: Shannon entropy of URL string and domain string.
  3. Implement domain/network extractors: IP address detection (regex matching standard and hex/octal formats), presence of security/banking keywords, TLD risk scores.
  4. Unit test feature extraction logic against known benign and malicious test URLs.

#### Task 1.4: Leak-Free Preprocessing Pipeline Architecture
* **Deliverable:** Scikit-learn Pipeline Object in Colab/Repository.
* **Step-by-Step Actions:**
  1. Partition data into Train (70%) and Test (30%) using stratified sampling with fixed `random_state=42`.
  2. Wrap preprocessing transformers in an `sklearn.pipeline.Pipeline`:
     * Numeric features: `SimpleImputer(strategy='median')` followed by `StandardScaler()`.
     * Categorical/TLD features: `OneHotEncoder(handle_unknown='ignore')`.
  3. Address class imbalance on the training split only using SMOTE, Random Under-Sampling, or `class_weight='balanced'`.
  4. Execute a formal data leakage audit confirming zero transformations were fitted on test data.

#### Task 1.5: Baseline Model Development & Benchmark Evaluation
* **Deliverable:** Baseline Model Evaluation Matrix and Checkpoint.
* **Step-by-Step Actions:**
  1. Instantiate and fit a baseline `LogisticRegression(max_iter=1000)` on the training split.
  2. Generate predictions on the untouched test split.
  3. Compute baseline metrics: Confusion Matrix, Accuracy, Precision, Recall, $F_1$-Score, and ROC-AUC.
  4. Write a technical critique explaining why accuracy is insufficient and documenting baseline shortcomings.

#### Task 1.6: Phase 1 Submission, GitHub Repo Setup & 10-Minute Oral Defense
* **Deliverable:** Clean GitHub Repository, Colab Notebook, and Slide Deck.
* **Step-by-Step Actions:**
  1. Establish GitHub repo structure: `/notebooks`, `/src`, `/data`, `README.md`, `requirements.txt`.
  2. Rehearse the 10-minute presentation allocating equal speaking time across all 3–4 members.
  3. Defend Phase 1 before instructors, demonstrating the Colab baseline.

---

### 10.2 Phase 2 Breakdown: Final System, Robustness & Defense (Weeks 5 – 10)

#### Task 2.1: Advanced Ensemble Modeling & Hyperparameter Optimization
* **Deliverable:** Model training scripts and comparison benchmarks.
* **Step-by-Step Actions:**
  1. Implement **Random Forest Classifier**: tune `n_estimators`, `max_depth`, `min_samples_split`.
  2. Implement **LightGBM Classifier**: tune `learning_rate`, `num_leaves`, `colsample_bytree`.
  3. Implement **XGBoost Classifier**: optimize with GPU acceleration in Colab.
  4. Optional Stretch: Train a 1D Character-Level CNN in Keras directly on raw tokenized URL strings.
  5. Conduct 5-fold Stratified Cross-Validation on training data using `GridSearchCV` or `Optuna`.
  6. Tabulate comparative results showcasing statistically verified improvements over the Phase 1 baseline.

#### Task 2.2: Threshold Tuning & Financial Business Cost Calibration
* **Deliverable:** Precision-Recall trade-off analysis and threshold selection module.
* **Step-by-Step Actions:**
  1. Extract predicted probability scores ($P(Y=1)$) on the test partition.
  2. Plot Precision-Recall Curves and ROC curves.
  3. Implement the business cost loss function: evaluate total financial penalty across thresholds from 0.05 to 0.95.
  4. Select the optimal operating threshold balancing low False Positive rates with maximum attack interception.

#### Task 2.3: Model Explainability Implementation (SHAP & LIME)
* **Deliverable:** XAI visualization dashboard and interpretability report chapter.
* **Step-by-Step Actions:**
  1. Initialize `shap.TreeExplainer` on the best-performing tree ensemble model.
  2. Compute global SHAP feature importance: generate beeswarm summary plots and bar plots.
  3. Generate local waterfall/force plots explaining:
     * High-confidence True Positive phishing URL.
     * High-confidence True Negative benign URL.
     * Misclassified False Positive (benign link flagged as malicious).
     * Misclassified False Negative (evasive phishing link that bypassed the model).
  4. Translate SHAP attribution values into plain-English security insights for SOC analysts.

#### Task 2.4: Adversarial Robustness & Evasion Testing Suite
* **Deliverable:** Adversarial testing notebook and evaluation report.
* **Step-by-Step Actions:**
  1. Build an adversarial URL generator simulating real attacker evasion tricks:
     * Obfuscation by appending trusted parameters (e.g., `?verify=chase.com`).
     * Length padding with random alphanumeric noise.
     * Replacing standard characters with hex or URL-encoded equivalents.
     * Typosquatting / IDN homograph variations.
  2. Feed perturbed URLs into the trained models and measure performance degradation (% drop in Recall).
  3. Propose defensive hardening strategies (e.g., adversarial data augmentation or feature trimming).

#### Task 2.5: Interactive Web Demo Development (Streamlit / Flask)
* **Deliverable:** Working interactive web application.
* **Step-by-Step Actions:**
  1. Serialize the best-trained pipeline using `joblib` or `pickle`.
  2. Build a user interface in Streamlit or Flask containing:
     * Input field to paste any arbitrary URL.
     * Dynamic feature extraction visualizer (displays extracted URL attributes).
     * Risk gauge / probability score meter with color-coded alerts (Safe / Suspicious / Phishing).
     * Interactive SHAP feature breakdown highlighting specific red flags that caused the score.
  3. Test with both live benign banking URLs and known real phishing URLs.

#### Task 2.6: Comprehensive Technical Report (10–15 Pages)
* **Deliverable:** Publication-grade PDF report.
* **Step-by-Step Actions:**
  1. Author the 10–15 page report following standard academic formatting:
     * Abstract, Problem Statement & Industry Background.
     * Dataset Documentation & Leakage-Free Preprocessing Architecture.
     * Model Architectures, Experimental Setup & CV Results.
     * Explainability Analysis & Case Studies.
     * Adversarial Evasion Findings & Mitigation.
     * Deployment Constraints, Infrastructure Costs & Business ROI.
     * Ethical Considerations, Dual-Use Risks & Limitations.
  2. Compile all charts, confusion matrices, and pipeline flowcharts.

#### Task 2.7: Final Oral Defense & Individual Contribution Audit
* **Deliverable:** 10-minute final slide presentation and Q&A demonstration.
* **Step-by-Step Actions:**
  1. Prepare a concise slide deck covering problem, architecture, comparative gains, XAI, robustness, and demo.
  2. Conduct a live demonstration of the web app scoring arbitrary URLs.
  3. Review Git commit histories to ensure individual code contributions align with oral responses.

---

## 11. Team Role Distribution & Git Strategy

To ensure seamless collaboration, prevent merge conflicts, and satisfy the individual contribution grading criterion (1.5 marks), team responsibilities are mapped across 3–4 members:

```
+---------------------------------------------------------------------------------------------------------+
|                                    TEAM RESPONSIBILITY MATRIX                                           |
+--------------------------------+--------------------------------------+---------------------------------+
| Team Member Role               | Phase 1 Focus Areas                  | Phase 2 Focus Areas             |
+--------------------------------+--------------------------------------+---------------------------------+
| Member 1:                      | * Dataset collection & verification  | * Random Forest & LightGBM/XGB  |
| Data Engineer & ML Lead        | * EDA & statistical profiling        | * Hyperparameter tuning (5-fold)|
|                                | * Leak-free pipeline architecture    | * Cross-validation benchmarking |
+--------------------------------+--------------------------------------+---------------------------------+
| Member 2:                      | * Feature extraction engine (regex,  | * Adversarial evasion generator |
| Cyber Domain & Security Lead   |   entropy, domain/TLD features)      | * Robustness testing suite      |
|                                | * Baseline Logistic Regression model | * Defense hardening strategies  |
+--------------------------------+--------------------------------------+---------------------------------+
| Member 3:                      | * Evaluation metrics implementation  | * SHAP & LIME implementation    |
| Evaluation & XAI Specialist    | * Confusion matrix & F1 analysis     | * FP & FN deep-dive case studies|
|                                | * Problem & market case research     | * Business cost loss function   |
+--------------------------------+--------------------------------------+---------------------------------+
| Member 4 (if 4-member team):   | * Git repo management & CI/CD setup  | * Streamlit/Flask Web Demo      |
| Software & Full-Stack Lead     | * Colab notebook standardization     | * Pipeline serialization (API)  |
|                                | * Proposal drafting & slide design   | * Final report & documentation  |
+--------------------------------+--------------------------------------+---------------------------------+
```
*(Note: If the team consists of 3 students, Member 4's responsibilities are divided equally among Members 1, 2, and 3).*

### GitHub Repository & Branching Workflow
1. **Branch Protection:** The `main` branch holds only validated, clean code. All development occurs on feature branches (`feature/data-pipeline`, `feature/xai-shap`, `feature/demo-app`).
2. **Commit Hygiene:** Each member commits their respective modules with descriptive commit messages (e.g., `feat: implement Shannon entropy calculation in feature_extractor.py`).
3. **Commit History Audit:** Individual marks depend directly on verifiable commits matching the claimed sections in the report.

---

## 12. Deliverables & Submission Guidelines

### 12.1 Phase 1 Deliverables (Week 4 Checkpoint - 8 Marks)
1. **Google Colab Notebook (Phase 1):** Fully runnable, demonstrating data ingestion, EDA charts, feature extraction, leak-free pipeline, and baseline model evaluation.
2. **GitHub Repository:** Initialized repo containing modular Python source code, documentation, and `requirements.txt`.
3. **Phase 1 Project Proposal Document:** 4–6 pages detailing the business case, dataset justification, pipeline structure, and baseline evaluation.
4. **Phase 1 Presentation Deck:** Slides for the 10-minute oral defense.

### 12.2 Phase 2 Deliverables (Week 10 Final - 12 Marks)
1. **Production-Ready Google Colab Notebook:** Complete end-to-end execution from data preprocessing to multi-model comparison, CV tuning, SHAP explainability, and adversarial evaluation.
2. **Interactive Web Application:** Working Streamlit or Flask dashboard capable of scoring URLs in real time with SHAP visualizations.
3. **10–15 Page Comprehensive Technical Report:** Formal academic document covering methodology, comparative benchmarks, XAI findings, robustness analysis, deployment strategy, and ethics.
4. **Final Slide Presentation & Live Demo:** 10-minute presentation followed by individual faculty Q&A.
5. **Final GitHub Repository:** Polished repository with full documentation, architectural diagrams, saved models, and clean commit history.

---

## 13. Ethical Considerations & Rulebook Compliance

In accordance with course guidelines:
1. **Permitted Data Only:** Strictly use public, anonymized, and cited datasets. **Never capture, sniff, or attack network traffic on a network you do not own.** All controlled tests must occur within isolated virtual environments or offline datasets.
2. **Dual-Use & Defense Policy:** This tool is developed strictly for defensive threat detection and security automation. Adversarial evasion techniques developed during Task 2.4 must only be used to evaluate and strengthen defensive model boundaries.
3. **Model Transparency:** No automated decision that impacts user access to banking services may be implemented as an unexplainable black box; explainability via SHAP/LIME is mandatory to allow human-in-the-loop auditability.
4. **Data Privacy:** Any proprietary customer identifiers or sensitive credentials extracted during real-world simulation must be immediately hashed or purged to comply with privacy frameworks (e.g., GDPR, Egyptian Personal Data Protection Law).

---

## 14. Project Milestones & Recommended Timeline

```
Week 1: Team formation, repository creation, dataset sourcing & verification.
Week 2: EDA, statistical analysis, and modular URL feature extraction engine.
Week 3: Leak-free pipeline design, train/test splitting, baseline model training.
Week 4: Metric analysis, proposal report completion, Phase 1 Defense (8 Marks).
Week 5: Advanced modeling (Random Forest, XGBoost, LightGBM) & 5-fold CV tuning.
Week 6: Model comparison, ROC/PR curves, and business-cost threshold optimization.
Week 7: Explainability implementation (SHAP TreeExplainer for FNs and FPs).
Week 8: Adversarial robustness testing (URL obfuscation/padding) & defense hardening.
Week 9: Streamlit/Flask web prototype development & report writing (10-15 pages).
Week 10: Dry runs, final code audit, Phase 2 Final Submission & Oral Defense (12 Marks).
```
