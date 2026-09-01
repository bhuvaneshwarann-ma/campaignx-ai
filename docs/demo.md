# CampaignX AI — End-to-End Demo Walkthrough

## Scenario 1: Multilingual Scam Telemetry to Syndicate Attribution
1. Open the SOC Dashboard (`/dashboard`) and inspect active syndicates.
2. Ingest an English scam message: `"URGENT: SBI account blocked. Verify KYC at https://sbi-kyc-verify-online.com or call +919876543210."`
3. Ingest a Hinglish scam message: `"Aapka SBI account suspend ho gaya hai. Verify karein: https://sbi-kyc-verify-online.com call +919876543210."`
4. The **Hybrid Correlation Engine** automatically correlates both incidents based on shared domain `sbi-kyc-verify-online.com` and phone `+919876543210`.
5. Open the Threat Graph to view connected nodes.
6. Click **View Evidence** to inspect canonical `OBSERVED` provenance.
7. Ask the AI Investigator: *"Why are these incidents connected?"*
8. Ingest a negative control (benign bank OTP): observe **RELATIONSHIP REJECTED** (False Positive Protection in action).

## Scenario 2: Technical IOC Pivoting & MITRE ATT&CK
1. In Universal Search, enter C2 IP: `185.220.101.5`.
2. Inspect multi-engine detections and risk score `92/100 (CRITICAL)`.
3. Pivot from IP → Malware (`FakeBank APK Stealer`) → Threat Actor (`PhantomRaven`) → ATT&CK (`T1566.002`).
4. Click **Export STIX / PDF** to download the structured STIX 2.1 JSON bundle.
