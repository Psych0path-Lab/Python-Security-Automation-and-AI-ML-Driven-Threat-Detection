# Part 4 (Q5) — Python Security Automation and AI/ML-Driven Threat Detection

Every script and the ML pipeline below has been run and verified — outputs shown are real, not illustrative, except where explicitly marked.

---

## Task 1 — Multithreaded Port Scanner with Banner Grabbing

[`port_scanner.py`](./port_scanner.py) — socket + threading only, no `nmap`/`subprocess` calls.

**Verified run** (against a throwaway local listener bound to port 9999 that replies with a banner, alongside 15 closed ports in the same range, to prove both the open-port and closed-port paths work):
```
$ python port_scanner.py 127.0.0.1 9990-10005 --timeout 0.5

Scan results for 127.0.0.1 (ports 9990-10005):

Port    State   Banner
------------------------------------------------------------
9999    open    220 test-service ready

1 open port(s) found.
```
The 15 closed ports in that range produced no output and no crash — confirming the `try/except` around `connect_ex`/`recv` handles connection-refused/timeout/OSError cleanly.

Design notes:
- A `threading.Semaphore` caps concurrent threads (default 200) so a large range like `1-65535` doesn't spawn tens of thousands of threads at once.
- The shared `results` list is guarded by a `threading.Lock` — without it, two threads' `list.append()` calls could interleave and corrupt or silently drop entries.
- Banner bytes are decoded with `errors="replace"` rather than the default strict mode, since not every service returns valid UTF-8.

---

## Task 2 — Log Parser with Regex IP Extraction and Threat Intelligence Enrichment

[`log_enricher.py`](./log_enricher.py) — extracts IPv4 addresses with `re`, skips private ranges, deduplicates with a `set`, enriches via `ip-api.com`.

**A real bug caught during testing, worth knowing about:** the first version used `ipaddress.ip_address(x).is_private`, which — beyond the RFC1918 ranges the task actually asks to skip — *also* excludes loopback, link-local, and the RFC 5737 documentation ranges (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`). That silently dropped legitimate "public" IPs like `203.0.113.5`. The fix in this repo checks membership against exactly the three ranges the assignment specifies (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`) instead of relying on the broader stdlib property — see the comment above `PRIVATE_RANGES` in the script.

**Verified output** (mock mode, [`sample_data/sample_firewall.log`](./sample_data/sample_firewall.log), which reuses the Q3 incident scenario — `203.0.113.5` is the same brute-force source IP, `10.0.2.20` the same compromised app server):
```
$ python log_enricher.py sample_data/sample_firewall.log --mock-dir sample_data/ip_api_mock
{
  "192.0.2.77": {
    "country": "Singapore",
    "isp": "Example Cloud Provider",
    "hosting": true,
    "proxy": true,
    "mobile": false
  },
  "198.51.100.23": {
    "country": "Germany",
    "isp": "Example Telecom GmbH",
    "hosting": false,
    "proxy": false,
    "mobile": false
  },
  "203.0.113.5": {
    "country": "United States",
    "isp": "Example Hosting LLC",
    "hosting": true,
    "proxy": true,
    "mobile": false
  }
}
```
The two private IPs also present in the log (`10.0.2.20`, `172.16.5.9`) are correctly excluded — only the three public addresses appear above.

**Live-mode verified** against the real `ip-api.com` API (not mocked):
```
$ echo "8.8.8.8 test log line" > test.log
$ python log_enricher.py test.log
{
  "8.8.8.8": {
    "country": "United States",
    "isp": "Google LLC",
    "hosting": false,
    "proxy": false,
    "mobile": false
  }
}
```

---

## Task 3 — Machine-Learning Threat Detector

[`ml_threat_detector.py`](./ml_threat_detector.py) — dataset: [UCI "Phishing Websites"](https://archive.ics.uci.edu/dataset/327/phishing+websites) (Mohammad, McCluskey — cited per the academic-integrity requirement for third-party datasets), bundled at [`data/phishing.csv`](./data/phishing.csv), 11,054 samples, 30 integer-encoded features, binary `result` label (`-1` = phishing, `1` = legitimate) — well over the required 5,000-sample minimum.

**Real run output:**
```
First 5 rows:
   having_ip_address  url_length  ...  statistical_report  result
0                 -1           1  ...                  -1      -1
1                  1           1  ...                   1      -1
2                  1           0  ...                  -1      -1
3                  1           0  ...                   1      -1
4                  1           0  ...                   1       1

[5 rows x 31 columns]

Class distribution (result: -1 = phishing, 1 = legitimate):
result
 1    6157
-1    4898
Name: count, dtype: int64

Rows dropped for nulls: 0
Non-numeric columns requiring encoding: none
Duplicate rows removed: 5206
Final row count: 5849
```
**5,206 duplicate rows** — nearly half the raw dataset — is a genuine, notable characteristic of this dataset (30 mostly-ternary features have limited possible combinations, so exact duplicates are common), not a bug. It's exactly what the "confirm there are no duplicate rows" requirement is designed to catch.

**Random Forest — full classification report:**
```
              precision    recall  f1-score   support

          -1       0.96      0.95      0.95       620
           1       0.94      0.95      0.95       550

    accuracy                           0.95      1170
   macro avg       0.95      0.95      0.95      1170
weighted avg       0.95      0.95      0.95      1170
```

**Isolation Forest — anomaly detection accuracy:** `0.5530`

**Model comparison:**

| Model | Accuracy | Precision | Recall | F1 Score | Notes |
|---|---|---|---|---|---|
| Random Forest | 0.9513 | 0.9513 | 0.9513 | 0.9513 | Supervised; trained on 80% split, `random_state=42`, default hyperparameters |
| Isolation Forest | 0.5530 | 0.5534 | 0.5530 | 0.5532 | Unsupervised; `contamination` set to the true minority-class proportion in training data; only marginally better than chance |

### Discussion (precision/recall vs. accuracy, F1, and limitations)

Raw accuracy can be misleading on security datasets because class imbalance is common — a detector that always predicts "benign" can still score high accuracy if malicious events are rare, while missing every real attack. Precision (of everything flagged malicious, how much actually was) and recall (of everything actually malicious, how much was caught) expose that failure mode directly: low recall means real intrusions slip through, while low precision means analysts drown in false positives — precisely the 2,000-alerts/day problem described elsewhere in this project. F1 is the harmonic mean of precision and recall, and it punishes models that trade one off heavily for the other, so it's a useful single number when both false positives and false negatives carry real cost. Here, Random Forest reached a genuinely strong 95% F1, but it needs labelled data and can silently misclassify attack patterns that don't resemble anything in its training set — a real limitation against novel, zero-day-style attacks. Isolation Forest, trained with no labels at all, scored only 55%, because this dataset's "malicious" class is roughly 45% of the data, not a genuinely rare outlier — exactly the assumption Isolation Forest depends on to work well; a real SOC's true attack rate would need to be far lower (true rare-event anomalies) for this unsupervised approach to be effective on its own.

*(≈200 words)*

---

## Task 4 — VirusTotal API v3 Enrichment

[`virustotal_check.py`](./virustotal_check.py) — key loaded from `VT_API_KEY` (never hardcoded), handles 404/401/429 and network errors without crashing.

**Verified — mock mode** (no live key was used or committed):
```
$ python virustotal_check.py 203.0.113.5 198.51.100.23 --mock-dir sample_data/virustotal_mock
{
  "203.0.113.5": {
    "malicious": 7,
    "harmless": 24,
    "last_analysis_date": "2024-01-01T00:00:00+00:00"
  },
  "198.51.100.23": {
    "malicious": 0,
    "harmless": 58,
    "last_analysis_date": "2024-01-01T00:00:00+00:00"
  }
}
```

**Verified — graceful failure with no API key set** (this is the real error path, not a simulated one):
```
$ python virustotal_check.py 8.8.8.8
{
  "8.8.8.8": {
    "error": "VT_API_KEY is not set — add it to .env or export it"
  }
}
```
### Input → Process → Output

Each script maps cleanly onto the automation mindset: **Input** is the raw, low-context data each script starts from (`port_scanner.py`: a target IP + port range; `log_enricher.py`: a raw log file; `ml_threat_detector.py`: a labelled CSV). **Process** is the transformation each script applies (`port_scanner.py`: TCP connection attempts + banner grabs; `log_enricher.py`: regex extraction + API lookups; `ml_threat_detector.py`: training and evaluating a classifier). **Output** is structured, decision-ready information instead of raw data (`port_scanner.py`: an open-ports table; `log_enricher.py`/`virustotal_check.py`: enriched JSON keyed by IP; `ml_threat_detector.py`: a benign/malicious classification with a confidence score) — the point of automation being that each stage's output is exactly the next stage's input, which is what makes chaining them into a pipeline (Task 5) possible at all.

---

## Task 5 — SOAR Workflow Description


In a SOAR pipeline, these four tools map onto three of its stages. `port_scanner.py` is **data collection** — it independently discovers what's actually listening on a host, feeding real exposure data into the platform rather than trusting a config file that may be stale. `log_enricher.py` and `virustotal_check.py` are both **enrichment** — each takes a raw indicator (an IP pulled from a log line) and attaches context (geolocation, ISP, hosting/proxy flags, vendor detection counts) so a human or a downstream rule has more than a bare IP to reason about. The ML threat detector is **detection** — it converts a raw observation into a classification, or with Isolation Forest, an anomaly score, that the platform can act on.

The Random Forest's output suits threshold-based routing well because scikit-learn exposes a probability via `predict_proba`, not just a hard label, so the SOAR platform can act on confidence rather than a binary yes/no. A high-confidence malicious classification (e.g. >90%, corroborated by VirusTotal detections) triggers **automated response** — blocking the IP at the firewall, the same action Part 2's SIEM correlation rule recommends for its scenario. A mid-confidence result (roughly 50–90%) is enriched further and escalated to a human analyst rather than acted on automatically; below that band, the event is logged but not surfaced, to control alert volume. This reflects the real trade-off in a SOC: too low a threshold causes false positives that auto-block legitimate traffic (an availability incident of its own), while too high a threshold lets true positives slip through unactioned as false negatives — the threshold should be tuned against the SOC's actual false-positive tolerance, not fixed abstractly.

---

## Repository Structure

```
README.md                  this document
port_scanner.py
log_enricher.py
virustotal_check.py
ml_threat_detector.py
requirements.txt
.env.example
.gitignore
data/
  phishing.csv              UCI Phishing Websites dataset (11,054 rows)
sample_data/
  sample_firewall.log       sample log for log_enricher.py
  ip_api_mock/              mock ip-api.com JSON responses (offline mode)
  virustotal_mock/          mock VirusTotal JSON responses (offline mode)
```

## Sources / Third-Party Data and Libraries

- Dataset: Mohammad, R. & McCluskey, L. (2012). *Phishing Websites* [Dataset]. UCI Machine Learning Repository. https://doi.org/10.24432/C51W2X
- requests — https://pypi.org/project/requests/
- pandas — https://pandas.pydata.org
- scikit-learn — https://scikit-learn.org
- ip-api.com — https://ip-api.com
- VirusTotal API v3 — https://docs.virustotal.com/reference/overview
