# Datasets

All data is public. Raw files live in `data/raw/` and are **not committed to Git** (size and licences).

**Mirror:** an exact copy of `data/raw/` is in this [public Google Drive folder](https://drive.google.com/drive/folders/1w_0md9dmjnYGvht6pmoRgVm0mA4EkI0_). `notebooks/phase1.ipynb` downloads the files it needs from there automatically with `gdown`. The original sources are listed below.

| Folder | Dataset | Used for | Rows | Licence | Downloaded |
|---|---|---|---|---|---|
| `raw/phiusiil/` | **PhiUSIIL Phishing URL Dataset**, UCI #967, Prasad & Chandra (2024) | **Training, validation and test** | 235,795 URLs (134,850 legit, 100,945 phishing) | CC BY 4.0 | 2026-11-21 |
| `raw/openphish/` | **OpenPhish community feed** (`feed_YYYY-MM-DD.txt`) | Fresh-phishing sanity check (Phase 1), drift test (Phase 2) | about 300 URLs per snapshot | OpenPhish community feed terms (free, non-commercial) | 2026-11-21 |
| `raw/tranco/` | **Tranco Top-1M** list (id `46YVX`) | Benign domain reference and bank domains for FP testing | 1,000,000 domains | Free for research, cite Le Pochat et al. (NDSS 2019) | 2026-11-21 |
| `raw/iscx/malicious_phish.csv` | **Kaggle "Malicious URLs dataset"** (Manu Siddhartha), built partly from ISCX-URL2016 | External **benign-only** check (legit URLs with paths) | 651,191 URLs | Check the Kaggle page | 2026-11-21 |
| `raw/iscx/Phishing.csv` | ISCX-URL2016 lexical feature file (CIC, UNB) | Not used: pre-computed features with no raw URLs | 15,367 rows | CIC terms, cite Mamun et al. (2016) | 2026-11-21 |
| `raw/uci_phishing_websites/` | UCI Phishing Websites #327, Mohammad et al. | Not used: pre-computed −1/0/1 features with no raw URLs | 11,055 rows | CC BY 4.0 | 2026-11-21 |

**Download links**
- PhiUSIIL: https://archive.ics.uci.edu/dataset/967/phiusiil+phishing+url+dataset
- OpenPhish: https://openphish.com/feed.txt
- Tranco: https://tranco-list.eu/
- Kaggle Malicious URLs: https://www.kaggle.com/datasets/sid321axn/malicious-urls-dataset
- ISCX-URL2016: https://www.unb.ca/cic/datasets/url-2016.html
- UCI #327: https://archive.ics.uci.edu/dataset/327/phishing+websites

**Not available:** PhishTank (`data.phishtank.com`) returned HTTP 403 on 2026-11-21 because it needs an API key. URLhaus `csv_recent` returned HTTP 410.

## Known issues (found during EDA)

1. **The PhiUSIIL label is inverted:** `label = 1` means **legitimate**. The notebook flips it so that `1 = phishing`.
2. **There are collection shortcuts in PhiUSIIL.** 100% of legit URLs are `https://www.<domain>` with no path. In the phishing class, 48.7% use https, 41.4% have `www.` and 28.4% have a path. A model that sees the full URL learns these artefacts instead of phishing, so the features are computed from the **hostname only**, after removing the scheme, `www.`, the port and the path.
3. **There is a residual subdomain shortcut.** After removing `www.`, only about 4% of PhiUSIIL legit hosts have a subdomain, against 54.5% of phishing hosts (about 25% in Kaggle benign). This cannot be removed because the subdomain is part of the hostname, so the baseline over-flags legit subdomains such as `online.cibeg.com`. It is documented as a limitation, and the planned Phase 2 fix is adding benign hosts from Kaggle or Tranco.
4. **The Kaggle phishing class has label noise.** About 23% of its "phishing" rows are on Tranco top-10k domains (`ietf.org`, `wikipedia.org`, `google.com`, ...). Only its benign class is used.
