# VCA-sense

## 🧭Overview

**VCA-sense** is a comprehensive benchmarking suite designed to evaluate link anomalies. It includes two datasets collected from various scenarios (voice, video, and screen sharing) on Feishu and Tencent Meeting, along with three algorithms capable of computing forward and backward packet loss rates for **QUIC**, **RTP**, and **TCP** streams.

VCA-sense enables researchers to conveniently analyze conference software traffic under different conditions and accurately estimate packet loss before and after intermediate nodes using multiple loss analysis algorithms.

---

## 🚀Usage

### 🗂️dataset

The two datasets in the `data` directory contain PCAP files captured from **Feishu Meeting** and  **Tencent Meeting** .

They include multiple application scenarios such as  **audio-only streams** ,  **video streams** ,  **screen-sharing streams** , and  **combinations of these** .

These datasets enable researchers to perform quantitative analyses of traffic characteristics under different conferencing scenarios.

### 🧰algorithm

**Pseudocode**

**Input:** Stream of packets with identifier `S`, and IP ID `ip_id`
**Output:** Classification of loss events

Initialize `max_seq ← -1`

Initialize ordered map `packets_map`

For each incoming packet `p` with `(S, ip_id)`:

* If `S > max_seq`:
  * `max_seq ← S`
  * Insert `(S, ip_id)` into `packets_map`
* Else:
  * If `S` in `packets_map` **and** `ip_id - packets_map[S] ≥ 3`:
    * Mark packet `S` as **forward loss**
  * Else if `ip_id - packets_map[lower_bound(S)] ≥ 3`:
    * Mark packet `S` as **backward loss**

The forward and backward packet loss analysis supports multiple types of PCAP files, including **TCP**, **QUIC**, and **UDP**.
Each protocol has its own processing algorithm under the corresponding directory. The usage methods are as follows:

---

- **QUIC**

  First, update the path to `tshark` in the `quic_processor.py` file:

  ```bash
  TSHARK_PATH="<tshark_path>"
  ```

Then, run `quic_processor.py` with the input PCAP file and TLS key to generate preprocessed streams grouped by `"IP:Port"`:

<pre class="overflow-visible!" data-start="2144" data-end="2225"><div class="contain-inline-size rounded-2xl relative bg-token-sidebar-surface-primary"><div class="sticky top-9"><div class="absolute end-0 bottom-0 flex h-9 items-center pe-2"><div class="bg-token-bg-elevated-secondary text-token-text-secondary flex items-center gap-4 rounded-sm px-2 font-sans text-xs"></div></div></div><div class="overflow-y-auto p-4" dir="ltr"><code class="whitespace-pre! language-bash"><span><span>python quic_processor.py <pcap_file> <tls_keys_file> <output_dir>
</span></span></code></div></div></pre>

Use `loss_rate.py` to calculate the forward and backward packet loss rates for each preprocessed stream:

<pre class="overflow-visible!" data-start="2337" data-end="2384"><div class="contain-inline-size rounded-2xl relative bg-token-sidebar-surface-primary"><div class="sticky top-9"><div class="absolute end-0 bottom-0 flex h-9 items-center pe-2"><div class="bg-token-bg-elevated-secondary text-token-text-secondary flex items-center gap-4 rounded-sm px-2 font-sans text-xs"></div></div></div><div class="overflow-y-auto p-4" dir="ltr"><code class="whitespace-pre! language-bash"><span><span>python loss_rate.py <pcap_file>
</span></span></code></div></div></pre>

---

* **RTP**
  First, update the path to `tshark` in the `rtp_processor.py` file:

  <pre class="overflow-visible!" data-start="2474" data-end="2520"><div class="contain-inline-size rounded-2xl relative bg-token-sidebar-surface-primary"><div class="sticky top-9"><div class="absolute end-0 bottom-0 flex h-9 items-center pe-2"><div class="bg-token-bg-elevated-secondary text-token-text-secondary flex items-center gap-4 rounded-sm px-2 font-sans text-xs"></div></div></div><div class="overflow-y-auto p-4" dir="ltr"><code class="whitespace-pre! language-bash"><span><span>DEFAULT_TSHARK=</span><span>"<tshark_path>"</span><span>
  </span></span></code></div></div></pre>

  Then, run `rtp_processor.py` with the input PCAP file to generate preprocessed streams grouped by `"IP:Port"`:

  <pre class="overflow-visible!" data-start="2638" data-end="2689"><div class="contain-inline-size rounded-2xl relative bg-token-sidebar-surface-primary"><div class="sticky top-9"><div class="absolute end-0 bottom-0 flex h-9 items-center pe-2"><div class="bg-token-bg-elevated-secondary text-token-text-secondary flex items-center gap-4 rounded-sm px-2 font-sans text-xs"></div></div></div><div class="overflow-y-auto p-4" dir="ltr"><code class="whitespace-pre! language-bash"><span><span>python rtp_processor.py <pcap_file>
  </span></span></code></div></div></pre>

  Finally, use `loss_rate.py` to calculate the forward and backward packet loss rates for each preprocessed stream:

  <pre class="overflow-visible!" data-start="2810" data-end="2857"><div class="contain-inline-size rounded-2xl relative bg-token-sidebar-surface-primary"><div class="sticky top-9"><div class="absolute end-0 bottom-0 flex h-9 items-center pe-2"><div class="bg-token-bg-elevated-secondary text-token-text-secondary flex items-center gap-4 rounded-sm px-2 font-sans text-xs"></div></div></div><div class="overflow-y-auto p-4" dir="ltr"><code class="whitespace-pre! language-bash"><span><span>python loss_rate.py <pcap_file>
  </span></span></code></div></div></pre>

---

* **TCP**
  For TCP, both preprocessing and loss rate calculation are integrated into a single script. Run the following command directly:
  <pre class="overflow-visible!" data-start="3007" data-end="3058"><div class="contain-inline-size rounded-2xl relative bg-token-sidebar-surface-primary"><div class="sticky top-9"><div class="absolute end-0 bottom-0 flex h-9 items-center pe-2"><div class="bg-token-bg-elevated-secondary text-token-text-secondary flex items-center gap-4 rounded-sm px-2 font-sans text-xs"></div></div></div><div class="overflow-y-auto p-4" dir="ltr"><code class="whitespace-pre! language-bash"><span><span>python tcp_loss_rate.py <pcap_file>
  </span></span></code></div></div></pre>

---

## 📈Result

We evaluated the algorithm performance under various forward and backward loss rate conditions.

The results are shown below:

![1761306853497](image/README/1761306853497.png)

In most scenarios, the deviation between measured and actual loss rates remains within  **1%** , demonstrating high accuracy.
