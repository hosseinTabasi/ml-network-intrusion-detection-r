# Machine Learning Network Intrusion Detection System in R

**Author:** Hossein Tabasi  
**Repository:** [https://github.com/hosseinTabasi/ml-network-intrusion-detection-r](https://github.com/hosseinTabasi/ml-network-intrusion-detection-r)

University course project. A network **intrusion detection system (IDS)**, in the narrow sense used here, is a classifier that looks at *recorded connection features* (bytes transferred, TCP flags, counts in a short time window, and so on) and labels the connection as **normal** or **attack**. This repository does that offline on the public NSL-KDD benchmark. It is **not** a packet sniffer, it does not open raw sockets, and it does not capture live traffic.

The fitted models are evaluated on the official **KDDTest+** split. High accuracy on this 1990s-era benchmark is common and still does **not** mean the code is a real IDS for a modern network.

## What this project does

- Reads official `KDDTrain+.txt` / `KDDTest+.txt` (41 KDD features + label + difficulty).
- Builds a **binary** target: `normal` vs `attack` (every label other than `normal`).
- Uses attack *families* (DoS / Probe / R2L / U2R) **only for EDA plots**, not as a 5-class training target.
- Fits two models on a downsampled copy of KDDTrain+: an `rpart` decision tree and a Random Forest (`ntree = 100`).
- Reports accuracy, precision, recall, and F1 for **both** classes on **KDDTest+ only**.
- Saves the model with the highest **attack recall** (then attack F1, then accuracy) and serves it from a small Shiny form.

Attack-class recall is the headline number: missing an attack is worse than raising a false alarm on this task.

## Dataset

NSL-KDD is a refined version of KDD Cup 1999. Tavallaee et al. (2009) removed a large number of redundant records from KDD99 and published official train/test files with a more even difficulty mix. The original KDD99 traffic is still simulated, dated, and not a sample of today’s internet.

- Tavallaee, M., Bagheri, E., Lu, W., & Ghorbani, A. A. (2009). *A Detailed Analysis of the KDD CUP 99 Data Set.* IEEE CISDA.
- CIC / UNB page: https://www.unb.ca/cic/datasets/nsl.html

Files in [`data/`](data/) (see [`data/README.md`](data/README.md) for licence note and re-download commands):

| File | Rows | Role |
|------|-----:|------|
| `KDDTrain+.txt` | 125,973 | Official training table |
| `KDDTest+.txt`  | 22,544  | Official test table |

Binary counts:

| Split | normal | attack | total |
|-------|------:|------:|------:|
| KDDTrain+ | 67,343 | 58,630 | 125,973 |
| KDDTest+  | 9,711 | 12,833 | 22,544 |

The **official train/test files are used as-is**. Rows are never shuffled from train into test.

KDDTest+ contains 17 attack labels that do **not** appear in KDDTrain+ (`apache2`, `httptunnel`, `mscan`, `saint`, `processtable`, …). That distribution shift is a known property of the benchmark and is why attack recall on KDDTest+ is much harder than a random split of KDDTrain+ would suggest.

### Attack families (EDA only)

Standard NSL-KDD mapping on official KDDTrain+:

| Family | Count |
|--------|------:|
| normal | 67,343 |
| DoS    | 45,927 |
| Probe  | 11,656 |
| R2L    | 995 |
| U2R    | 52 |

On KDDTest+ the same mapping is 9,711 normal / 7,460 DoS / 2,421 Probe / 2,885 R2L / 67 U2R. R2L is much more common in the test file than in the train file.

### Feature subset (23 raw columns)

Full NSL-KDD has 41 features. Many of the rate features are near-duplicates (for example `serror_rate` vs `srv_serror_rate` vs `dst_host_serror_rate` vs `dst_host_srv_serror_rate`). This project keeps **23** columns that show up repeatedly in NSL-KDD papers and drops the redundant siblings plus near-constant fields (`num_outbound_cmds` is always 0; `land` / `urgent` are almost always 0).

**Categorical (kept):**

- `protocol_type` (tcp / udp / icmp)
- `flag` (SF, S0, REJ, …) — connection state, highly informative for SYN-flood style DoS
- `service` — 70+ application names, so it is **collapsed** to the 12 most frequent training values plus `rare` before dummy encoding. Top-12 on the fit set: `http`, `private`, `domain_u`, `smtp`, `ftp_data`, `eco_i`, `other`, `ecr_i`, `telnet`, `ftp`, `finger`, `auth`. (`other` here is a real NSL-KDD service name; rare leftover services are coded `rare`.)

**Numeric:**

`duration`, `src_bytes`, `dst_bytes`, `wrong_fragment`, `hot`, `logged_in`, `count`, `srv_count`, `serror_rate`, `rerror_rate`, `same_srv_rate`, `diff_srv_rate`, `dst_host_count`, `dst_host_srv_count`, `dst_host_same_srv_rate`, `dst_host_diff_srv_rate`, `dst_host_same_src_port_rate`, `dst_host_srv_diff_host_rate`, `dst_host_serror_rate`, `dst_host_rerror_rate`.

`duration`, `src_bytes`, and `dst_bytes` are `log1p`-transformed, then all numeric columns are standardised with **training** means and standard deviations. Dummy columns stay 0/1. After dummy encoding the model matrix has **47** columns.

### Downsample (TRAIN only)

KDDTrain+ is already close to balanced (53.5% normal). For a laptop-sized Random Forest:

1. Downsample the majority class to the minority size (without replacement).
2. Cap each class at **12,000** rows (`set.seed(42)`).

**Fit set: 24,000 rows (12,000 normal + 12,000 attack).**  
KDDTest+ is **not** downsampled. Evaluation uses all 22,544 test rows.

## Project layout

```
.
├── app.R                    # Shiny UI (feature sliders, Predict, optional CSV)
├── data/
│   ├── KDDTrain+.txt
│   ├── KDDTest+.txt
│   └── README.md
├── R/
│   ├── install_packages.R   # install.packages() if anything is missing
│   ├── prepare_data.R       # load, names, binary label, subset, dummy, scale, downsample
│   ├── eda.R                # ggplot2 PNGs in figures/
│   ├── train_models.R       # rpart + Random Forest, writes models/ and figures/
│   └── predict_connection.R # predict_connection() used by the app and smoke tests
├── models/                  # written by training; required by Shiny
├── figures/
└── README.md
```

## Packages

R 4.x. From an R session (or `Rscript`), at the project root:

```r
source("R/install_packages.R")
```

That script calls `install.packages()` only for packages that are not already installed, and retries a second CRAN mirror if needed. The list is:

```r
install.packages(c(
  "dplyr", "ggplot2", "readr", "tidyr", "tibble",
  "caret", "randomForest", "rpart", "shiny", "jsonlite"
))
```

`rpart` is the decision tree. `randomForest` is the second model (`ntree = 100`). `caret` is available for confusion-matrix helpers. `ggplot2` / `tidyr` draw the EDA figures. `shiny` is only needed to launch the app.

## How to train

From the **project root**:

```bash
Rscript R/train_models.R
```

What the script does:

1. Reads `data/KDDTrain+.txt` and `data/KDDTest+.txt` (downloads them if missing; see `data/README.md`).
2. Names the 43 columns, builds the binary target, and maps families for EDA.
3. Writes ggplot2 figures on the **full** official training table.
4. Downsamples KDDTrain+ as above (`seed = 42`, 12,000 per class).
5. Learns factor levels, dummy columns, `log1p` columns, and numeric scaler from that fit set only (no test leakage).
6. Fits **rpart** (`cp = 0.001`, `maxdepth = 16`) and **Random Forest** (`ntree = 100`, `mtry = floor(sqrt(p))`).
7. Scores **KDDTest+ only**: accuracy, precision, recall, F1 for both classes, plus a confusion matrix.
8. Saves the model with the highest attack recall (then attack F1, then accuracy).

Saved files (needed by Shiny and `predict_connection()`):

| File | Role |
|------|------|
| `models/best_model.rds` | Fitted `rpart` or `randomForest` object |
| `models/rpart_model.rds` / `rf_model.rds` | Both fitted models |
| `models/feature_recipe.rds` | Selected columns, top services, factor levels, dummy names, scaler, defaults |
| `models/feature_names.rds` | Column order at train time |
| `models/factor_levels.rds` | Training levels of `protocol_type`, `flag`, `service` |
| `models/scaler.rds` | Numeric centres / scales and `log1p` column list |
| `models/metrics.json` / `metrics.csv` | Test-set numbers from this run |

Re-run `Rscript R/train_models.R` after a clean clone if you want to retrain; it overwrites `models/` and `figures/`.

## How to launch Shiny

From the project root, after training:

```r
shiny::runApp()
```

or

```bash
Rscript -e "shiny::runApp('.', launch.browser = TRUE)"
```

Fill in about a dozen connection fields (protocol, flag, duration, byte counts, window counts, error rates, `logged_in`) and click **Predict**. Unused selected features are filled with training medians / modes. Optional CSV upload scores several rows at once.

The app shows **Normal vs Attack**, estimated P(attack), and a short note. If the RDS files are missing, it tells you to run `Rscript R/train_models.R` first.

Visible warning in the UI: this is a **teaching prototype, not a production IDS**; there is **no live packet capture**.

Shared scoring function (same path as the app):

```r
source("R/prepare_data.R")
source("R/predict_connection.R")
load_ids_model()
predict_connection(list(
  protocol_type = "tcp", flag = "SF", service = "http",
  duration = 0, src_bytes = 232, dst_bytes = 8153, logged_in = 1,
  count = 5, srv_count = 5, serror_rate = 0.20
))
```

## Main results

**Official KDDTest+, 22,544 connections, not reshuffled.**  
Fit set: 24,000 rows from KDDTrain+ (12,000 normal + 12,000 attack, `seed = 42`).  
23 raw features; 47 columns after dummy encoding.

| Model | Accuracy | Attack precision | Attack recall | Attack F1 | Normal precision | Normal recall | Normal F1 |
|-------|----------|------------------|---------------|-----------|------------------|---------------|-----------|
| rpart decision tree | 0.7826 | 0.9634 | 0.6424 | 0.7708 | 0.6719 | 0.9678 | 0.7931 |
| Random Forest (ntree = 100) | 0.7742 | 0.9677 | 0.6241 | 0.7588 | 0.6619 | 0.9725 | 0.7877 |

**Best model saved: rpart.** It is slightly better at *catching* attacks: test attack recall **0.6424** vs **0.6241** for Random Forest (8,244 / 12,833 attacks caught, vs 8,009 / 12,833). Attack precision is high for both (~0.96): when the tree says “attack”, it is usually looking at a SYN-flood / error-rate pattern that really is malicious in this file. The cost is **4,589** missed attacks (false negatives), many of them labels that never appear in KDDTrain+.

rpart test confusion matrix (rows = true):

|  | Pred normal | Pred attack |
|--|-------------|-------------|
| **True normal** | 9,398 | 313 |
| **True attack** | 4,589 | 8,244 |

Honesty check: **78.3% accuracy** on NSL-KDD is a routine number, not evidence of a deployable detector. KDDTest+ is about 57% attack, so accuracy is a weak headline. The useful number is attack recall **64.2%** with attack precision **96.3%** on this particular 1990s simulated corpus. That will not transfer to modern encrypted traffic, new protocols, or a live span port.

Plots written by the training script:

- `figures/class_balance.png` — binary counts on full KDDTrain+
- `figures/attack_family.png` — DoS / Probe / R2L / U2R / normal (EDA only)
- `figures/feature_boxplots.png` — duration, src_bytes, dst_bytes, count, serror_rate (`log1p`)
- `figures/correlation_heatmap.png` — selected numeric features
- `figures/confusion_matrix_best.png` — KDDTest+ for the saved model

## Example predictions

These are **live** calls of `predict_connection()` after the training run above, not hand-written labels. Values are NSL-KDD-style recorded features, not packets.

**1. HTTP-like row (normal-like)**

`protocol_type = tcp`, `flag = SF`, `service = http`, `duration = 0`, `src_bytes = 232`, `dst_bytes = 8153`, `logged_in = 1`, `count = 5`, `serror_rate = 0.20`

```
label: Normal
P(attack): 0.0024
note: Looks like a normal connection (rpart decision tree). Estimated P(attack) 0.2%. Teaching prototype only — not a production IDS.
```

**2. SYN-flood-like row (attack-like)**

`protocol_type = tcp`, `flag = S0`, `service = private`, `duration = 0`, `src_bytes = 0`, `dst_bytes = 0`, `logged_in = 0`, `count = 123`, `serror_rate = 1.00`

```
label: Attack
P(attack): 0.9933
note: Flagged as attack (rpart decision tree). Estimated P(attack) 99.3%. This is an offline classifier on recorded NSL-KDD-style features, not a live network monitor.
```

## Method notes

- **No leakage.** Scaler centres/scales, dummy columns, and the service top-12 list are learned on the downsampled training table only, then frozen and applied to KDDTest+ and to Shiny rows.
- **No random re-split.** The KDD Cup / NSL-KDD published split is the evaluation protocol.
- Decision threshold is **0.5** on estimated P(attack). Lowering it would raise attack recall and cost more false alarms; that trade-off is left as a student exercise.
- `rpart` probabilities are leaf frequencies, not well-calibrated probabilities. Treat them as a ranking score.
- `ntree = 100` and the 12,000-per-class cap are laptop budget choices (both models fitted in well under a minute on a CPU after EDA).

## Limitations

- **Old benchmark, not modern traffic.** NSL-KDD is derived from KDD Cup 1999 (DARPA 1998/99 simulated traces). Protocols, services, and attack mix are decades out of date. Encrypted web traffic, cloud APIs, and current malware are not in this file.
- **NSL-KDD improved KDD99 but did not make it “real”.** Redundant records were reduced and difficulty scores were added; the underlying feature schema and label process remain those of KDD99.
- **Official test is harder than the train file.** New attack names in KDDTest+ and a much larger R2L share mean that a tree which almost never false-alarms on neptune-style rows will still miss thousands of test attacks.
- **Offline features only.** The input is a row of already-computed KDD attributes. This project does not parse pcap, does not sniff interfaces, and must not be wired to a live network.
- **Not for real networks.** Do not treat the Shiny app, or the saved RDS files, as a security control. Do not scan or attack systems in order to “test” the classifier.
- **Feature and label issues.** KDD content features (`hot`, `num_failed_logins`, …) depend on a particular payload inspection setup. Labels come from the original simulation, not from a modern SOC.
- **Class imbalance inside “attack”.** U2R has 52 training rows; a binary downsample does not invent rare families. Family plots are descriptive only.
- **Laptop budget.** A larger forest, the full 125,973-row train table, or the full 41-feature set might move attack recall a little. That is outside the scope of this course project.

## Licence of the data

NSL-KDD is distributed by the Canadian Institute for Cybersecurity (University of New Brunswick) for research and teaching. Cite Tavallaee et al. (2009) if you use the corpus in academic work. Short version of source, counts, and re-download commands: [`data/README.md`](data/README.md).

Project code in this repository: Hossein Tabasi, for a university course.
