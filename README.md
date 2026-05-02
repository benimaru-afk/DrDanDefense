# Advanced Antivirus Suite ver.1.0.1

A machine-learning powered security dashboard for network threat detection and malware scanning.

---

## Installation

### 1 — Download

Click the green **Code** button on this GitHub page and choose **Download ZIP**.

### 2 — Extract

Extract the ZIP to wherever you want the app to live permanently (e.g. `C:\Program Files\AdvancedAntivirusSuite\` or your Desktop). Do **not** move individual files out of the folder after extraction — everything must stay together.

### 3 — Desktop shortcut (optional)

Open the extracted `Dashboard` folder and double-click **`install.bat`**.  
A shortcut called **Advanced Antivirus Suite** will appear on your Desktop.

> If Windows asks "Do you want to allow this app to make changes?", click **Yes**.  
> If your antivirus flags the `.bat`, you can safely allow it — it only creates a shortcut.

### 4 — Launch

Run **`Dashboard.exe`** (or use the Desktop shortcut).  
No Python installation is required.

---

## Training the Models

The app ships without pre-trained models. You must train them once before running network scans.  
Sample data is provided in the **`network-data/`** folder inside the extracted archive.

### Quick Scan model (Random Forest)

1. Open the app and go to the **Network** page.
2. Under **Quick Scan**, click **Traffic Scan**.
3. When the file picker opens, navigate to `network-data/` and select **`Train_data.csv`**.
4. Wait for training to complete — a confirmation message will appear.
5. To verify, click **Traffic Scan** again and select **`Test_data.csv`**.  
   Results should appear in the Last Scan Results panel.

### Deep Scan model (Random Forest + KMeans ensemble)

Repeat the same steps under the **Deep Scan** card using the same `Train_data.csv` and `Test_data.csv` files.  
Deep Scan takes longer but catches anomalous traffic that the Quick Scan model may miss.

---

## Live Scan

The **Live Scan** button captures 30 seconds of live network traffic and runs it through whichever model you select (Quick or Deep). It requires:

- **Npcap** installed — download from [https://npcap.com/#download](https://npcap.com/#download)  
  *(free, installs in under a minute, no reboot needed)*

Without Npcap, Live Scan will prompt you to install it or run the app as Administrator.

---

## Email Notifications

Go to **My Account**, log in with your email address, and verify with the code sent to your inbox.  
Once logged in you can toggle attack alert emails on or off from the account page.

---

## Threat Levels

| Colour | Meaning |
|--------|---------|
| Green  | No threats detected |
| Yellow | Suspicious activity (< 5 % of traffic flagged) |
| Red    | Threats detected (≥ 5 % of traffic flagged) |

---

## Troubleshooting

| Problem | Fix |
|---------|-----|
| "No trained model found" | Train a model first using Traffic Scan → `Train_data.csv` |
| Live Scan fails immediately | Install Npcap from npcap.com, or run the exe as Administrator |
| Scan results don't update on Dashboard | Switch to the Dashboard tab — it refreshes on each visit |
| App opens and closes instantly | Right-click `Dashboard.exe` → Run as administrator |

---

## Authors

| Name | GitHub |
|------|--------|
| Benjamin Mannal | [@benimaru-afk](https://github.com/benimaru-afk) |
| Christopher Esquibel | [@ChrisEsqui72](https://github.com/ChrisEsqui72) |
| Jaxen Bujold | [@JaxenBujy](https://github.com/JaxenBujy) |
| Katelynn Rainey | [@krainey1](https://github.com/krainey1) |
| Suhithareddy Kantareddy | [@suhithak-12](https://github.com/suhithak-12) |

---

## License

MIT License

Copyright (c) 2026 Benjamin Mannal, Christopher Esquibel, Jaxen Bujold, Katelynn Rainey, Suhithareddy Kantareddy

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
