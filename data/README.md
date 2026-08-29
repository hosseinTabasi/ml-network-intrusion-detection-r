# Dataset

## Files

- `KDDTrain+.txt` — official NSL-KDD training connections (no header row)
- `KDDTest+.txt` — official NSL-KDD test connections (no header row)

Each row has **43** comma-separated fields: the 41 KDD features, the attack
label, and a difficulty score. Column names used by this project:

```
duration, protocol_type, service, flag, src_bytes, dst_bytes, land,
wrong_fragment, urgent, hot, num_failed_logins, logged_in, num_compromised,
root_shell, su_attempted, num_root, num_file_creations, num_shells,
num_access_files, num_outbound_cmds, is_host_login, is_guest_login, count,
srv_count, serror_rate, srv_serror_rate, rerror_rate, srv_rerror_rate,
same_srv_rate, diff_srv_rate, srv_diff_host_rate, dst_host_count,
dst_host_srv_count, dst_host_same_srv_rate, dst_host_diff_srv_rate,
dst_host_same_src_port_rate, dst_host_srv_diff_host_rate,
dst_host_serror_rate, dst_host_srv_serror_rate, dst_host_rerror_rate,
dst_host_srv_rerror_rate, label, difficulty
```

## Source

NSL-KDD is a refined version of the KDD Cup 1999 corpus, built to reduce
redundant records and to provide a more even difficulty distribution.

- Tavallaee, M., Bagheri, E., Lu, W., & Ghorbani, A. A. (2009).
  *A Detailed Analysis of the KDD CUP 99 Data Set.* Proceedings of the
  IEEE Symposium on Computational Intelligence for Security and Defense
  Applications (CISDA).
- Dataset page (Canadian Institute for Cybersecurity / UNB):
  https://www.unb.ca/cic/datasets/nsl.html

This copy was downloaded from the public GitHub mirror of the same files:

```
https://raw.githubusercontent.com/jmnwong/NSL-KDD-Dataset/master/KDDTrain%2B.txt
https://raw.githubusercontent.com/jmnwong/NSL-KDD-Dataset/master/KDDTest%2B.txt
```

Row counts in this directory (must match the official release):

| File | Rows |
|------|------|
| KDDTrain+.txt | 125,973 |
| KDDTest+.txt  | 22,544 |

## How to re-download

From the project root:

```bash
mkdir -p data
curl -L -o data/KDDTrain+.txt \
  "https://raw.githubusercontent.com/jmnwong/NSL-KDD-Dataset/master/KDDTrain%2B.txt"
curl -L -o data/KDDTest+.txt \
  "https://raw.githubusercontent.com/jmnwong/NSL-KDD-Dataset/master/KDDTest%2B.txt"
wc -l data/KDDTrain+.txt data/KDDTest+.txt
```

`R/prepare_data.R` will also download the two files into `data/` if they are
missing.

## Licence / terms of use

NSL-KDD is distributed by the Canadian Institute for Cybersecurity (University
of New Brunswick) for **research and teaching**. It is supplied as a public
benchmark; check the CIC/UNB dataset page for the current terms before any
commercial use. Cite Tavallaee et al. (2009) in academic work.

The files in this folder are the original train/test tables. Do not rename a
modified extract as `KDDTrain+.txt` / `KDDTest+.txt`.

## Split used by this project

Training and evaluation use the **official** KDDTrain+ / KDDTest+ files. The
scripts do **not** shuffle train rows into the test set. A random subset of
KDDTrain+ is used only to *fit* the models (majority downsample + per-class
cap); evaluation is always on full KDDTest+.
