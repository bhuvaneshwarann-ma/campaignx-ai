"""
Synthetic Dataset & Ground Truth Generator for CampaignX AI.
Generates realistic multilingual scam messages and IOC-based incidents
grouped into campaigns with shared infrastructure and negative controls.
"""

import json
import random
from datetime import datetime, timedelta, timezone
from pathlib import Path

random.seed(42)  # Deterministic seed for reproducible testing & offline mode

DATA_DIR = Path(__file__).resolve().parent.parent.parent.parent / "data"
DATA_DIR.mkdir(parents=True, exist_ok=True)


# Multilingual message templates
TEMPLATES = {
    "english": {
        "bank_kyc": [
            "URGENT: Your {bank} account #{acc} is blocked due to pending KYC verification. Update immediately at {url} or call {phone} to prevent permanent suspension.",
            "Dear Customer, your {bank} netbanking services are suspended. Please complete PAN/Aadhaar update at {url}. Contact support at {phone}.",
            "ALERT: Unauthorized login attempt detected on your {bank} account. To secure your account, send ₹1 verification to UPI {upi} or click {url}."
        ],
        "delivery_courier": [
            "Important: Your parcel #{parcel} from {courier} cannot be delivered due to incorrect address. Pay ₹25 redelivery fee at {upi} or visit {url}.",
            "{courier} Alert: Package delayed at customs. Contact delivery agent at {phone} or update address at {url} within 24 hours."
        ],
        "job_scam": [
            "Congratulations! You are shortlisted for Part-Time Assistant role earning ₹50,000/month. Contact HR on WhatsApp at {phone} or visit {url}.",
            "Work from home daily earning ₹3000-₹8000 by rating apps. Message our recruiter at {phone} to join our Telegram group."
        ],
        "utility_power": [
            "URGENT: Dear Consumer, your electricity power will be disconnected tonight at 9:30 PM due to unpaid bill of previous month. Immediately call officer at {phone}."
        ]
    },
    "hindi": {
        "bank_kyc": [
            "आवश्यक सूचना: आपका {bank} खाता केवाईसी पूरा न होने के कारण आज बंद हो जाएगा। तुरंत {url} पर जाएं या {phone} पर संपर्क करें।",
            "प्रिय ग्राहक, आपके बैंक खाते में अनधिकृत गतिविधि देखी गई है। सुरक्षित करने के लिए {upi} पर ₹1 भेजकर पुष्टि करें या {url} देखें।"
        ],
        "utility_power": [
            "प्रिय उपभोक्ता, आपके पिछले महीने का बिजली बिल अपडेट न होने के कारण आज रात बिजली काट दी जाएगी। तुरंत बिजली अधिकारी {phone} से संपर्क करें।"
        ]
    },
    "hinglish": {
        "bank_kyc": [
            "URGENT ALERT: Aapka {bank} account block ho gaya hai. KYC update karne ke liye turant is link pe click karein: {url} ya call karein {phone}.",
            "Dear Customer, aapke {bank} debit card reward points ₹7,850 expire ho rahe hain. Redeem karne ke liye visit karein {url} ya UPI {upi} pe check karein.",
            "Aapke account se ₹45,000 deduct hone ki request aayi hai. Agar aapne nahi kiya toh turant cancel karein {url} pe ya contact karein {phone}."
        ],
        "delivery_courier": [
            "Aapka parcel deliver nahi ho paya. Redelivery charge ₹15 pay karein is UPI id pe: {upi} ya address update karein {url} pe."
        ]
    },
    "tamil": {
        "bank_kyc": [
            "முக்கிய அறிவிப்பு: உங்கள் {bank} கணக்கு கேஒய்சி (KYC) புதுப்பிக்கப்படாததால் முடக்கப்பட்டுள்ளது. உடனடியாக {url} தளத்தில் புதுப்பிக்கவும் அல்லது {phone} எண்ணை தொடர்பு கொள்ளவும்.",
            "அன்பார்ந்த வாடிக்கையாளரே, உங்கள் கணக்கில் சந்தேகத்திற்குரிய பரிவர்த்தனை நடந்துள்ளது. சரிபார்க்க {phone} அழைக்கவும்."
        ]
    },
    "tanglish": {
        "bank_kyc": [
            "Alert: Unga {bank} account KYC expire aagiruchu. Account block aagama iruka உடனே {url} link click panni update pannunga or call {phone}.",
            "Dear Customer, unga account-la irunthu ₹25,000 transfer initiate aagiruku. Cancel panna contact {phone} or open {url}."
        ],
        "job_scam": [
            "Part time job opportunity daily 2 hours work ₹2000-₹5000 earn pannalam. WhatsApp pannunga {phone} or register {url}."
        ]
    }
}

BANKS = ["SBI", "HDFC", "ICICI", "Axis Bank", "Punjab National Bank", "Kotak Bank", "Paytm Payments Bank"]
COURIERS = ["IndiaPost", "BlueDart", "Delhivery", "DTDC", "FedEx"]

# Ground truth campaigns configuration
CAMPAIGN_SPECS = [
    {
        "campaign_id": "CAM-001",
        "name": "State Bank KYC SMS Phishing Syndicate",
        "target": "bank",
        "detail": "SBI / HDFC KYC Suspension",
        "phones": ["+919876543210", "+919876543211"],
        "upis": ["sbikyc.verify@okhdfcbank", "secure.kyc@paytm"],
        "domains": ["sbi-kyc-verify-online.com", "update-bank-kyc-secure.net"],
        "ips": ["185.220.101.5", "194.26.29.112"],
        "hashes": ["e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"],
        "malware": "FakeBank APK Stealer",
        "actor": "PhantomRaven",
        "tactics": ["urgency_pressure", "authority_impersonation", "credential_harvesting"],
        "languages": ["english", "hindi", "hinglish"],
        "incident_count": 28
    },
    {
        "campaign_id": "CAM-002",
        "name": "Electricity Bill Power Disconnection Extortion",
        "target": "telecom",
        "detail": "State Electricity Board Power Cut Alert",
        "phones": ["+919123456789", "+919123456780"],
        "upis": ["bijlibill.pay@okaxis", "powerbill.support@ybl"],
        "domains": ["bill-payment-portal-online.org"],
        "ips": ["45.142.166.11", "91.240.118.89"],
        "hashes": ["5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8"],
        "malware": "QuickSupport Remote Trojan",
        "actor": "VoltScammer",
        "tactics": ["urgency_pressure", "authority_pressure", "payment_redirection"],
        "languages": ["english", "hindi", "hinglish", "tamil", "tanglish"],
        "incident_count": 22
    },
    {
        "campaign_id": "CAM-003",
        "name": "Postal Courier Redelivery Fee Harvester",
        "target": "delivery_courier",
        "detail": "IndiaPost & BlueDart Unclaimed Parcel Scam",
        "phones": ["+919988776655", "+919988776654"],
        "upis": ["indiapost.redelivery@icici", "customs.fee@apl"],
        "domains": ["indiapost-tracking-update.com", "courier-redelivery-hub.info"],
        "ips": ["103.208.86.12", "193.106.191.45"],
        "hashes": ["8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918"],
        "malware": "SmsForwarder Spyware",
        "actor": "CourierJackal",
        "tactics": ["artificial_scarcity", "trust_building", "payment_redirection"],
        "languages": ["english", "hinglish", "tanglish"],
        "incident_count": 20
    },
    {
        "campaign_id": "CAM-004",
        "name": "Telegram App-Rating Work-From-Home Task Fraud",
        "target": "employer",
        "detail": "YouTube / App Rating High Yield Investment Scam",
        "phones": ["+918877665544", "+918877665533"],
        "upis": ["taskreward.vip@okaxis", "merchant.fund@paytm"],
        "domains": ["global-task-earnings.vip", "app-review-wealth.com"],
        "ips": ["178.128.240.19", "167.99.145.22"],
        "hashes": ["4b227777d4dd1fc61c6f884f48641d02b4d121d3fd328cb08b5531fcacdabf8a"],
        "malware": "None",
        "actor": "SilkTiger Syndicate",
        "tactics": ["trust_building", "isolation_tactic", "payment_redirection"],
        "languages": ["english", "hinglish", "tanglish"],
        "incident_count": 25
    },
    {
        "campaign_id": "CAM-005",
        "name": "Law Enforcement Video Call Digital Arrest Scam",
        "target": "law_enforcement",
        "detail": "CBI / Mumbai Cyber Crime Parcel Drug Impersonation",
        "phones": ["+917766554433", "+917766554422"],
        "upis": ["cbi.official.clearance@sbi", "cybercell.narcotics@hdfc"],
        "domains": ["cbi-clearance-verification.in"],
        "ips": ["195.123.245.90"],
        "hashes": ["ef2d127de37b942baad06145e54b0c619a1f22327b2ebbcfbec78f5564afe39d"],
        "malware": "VideoRecord Extortion Toolkit",
        "actor": "ShadowArrest",
        "tactics": ["fear_induction", "authority_impersonation", "isolation_tactic"],
        "languages": ["english", "hindi", "hinglish"],
        "incident_count": 18
    }
]

# Negative controls designed specifically to test false positive resistance
NEGATIVE_CONTROLS = [
    {
        "incident_id": "INC-NEG-001",
        "channel": "sms",
        "language": "english",
        "raw_content": "URGENT: Your SBI bank account OTP for login is 492018. Do not share OTP with anyone.",
        "note": "Legitimate automated OTP message, contains KYC/bank keywords but benign."
    },
    {
        "incident_id": "INC-NEG-002",
        "channel": "email",
        "language": "english",
        "raw_content": "Dear Customer, your HDFC bank monthly statement is ready for download. Please log in to your official netbanking portal.",
        "note": "Legitimate banking statement notification."
    },
    {
        "incident_id": "INC-NEG-003",
        "channel": "sms",
        "language": "hinglish",
        "raw_content": "Aapka bank account urgent verify karein. Contact local branch office or visit our physical branch.",
        "note": "Generic keywords without any phone/UPI/URL overlap with active scam campaigns."
    },
    {
        "incident_id": "INC-NEG-004",
        "channel": "whatsapp",
        "language": "tamil",
        "raw_content": "வங்கி சேவை அறிவிப்பு: உங்கள் கணக்கில் KYC சரிபார்ப்பு முடிந்தது. நன்றி.",
        "note": "Benign completion notification in Tamil."
    },
    {
        "incident_id": "INC-NEG-005",
        "channel": "sms",
        "language": "english",
        "raw_content": "IndiaPost delivery update: Your package was delivered successfully today. Rate your delivery experience at official indiapost.gov.in.",
        "note": "Benign official IndiaPost message."
    }
]


def generate_synthetic_dataset(num_incidents: int = 250):
    """Generate deterministic synthetic incidents, campaigns, ground truth annotations."""
    all_incidents = []
    base_time = datetime(2026, 8, 1, 10, 0, 0, tzinfo=timezone.utc)
    inc_counter = 1

    # Generate incidents for each defined campaign
    for camp in CAMPAIGN_SPECS:
        for i in range(camp["incident_count"]):
            inc_id = f"INC-{inc_counter:04d}"
            lang = random.choice(camp["languages"])
            target_key = "bank_kyc" if camp["target"] == "bank" else ("delivery_courier" if camp["target"] == "delivery_courier" else ("job_scam" if camp["target"] == "employer" else "utility_power"))
            
            # Select template
            templates = TEMPLATES.get(lang, TEMPLATES["english"]).get(target_key, TEMPLATES["english"]["bank_kyc"])
            template = random.choice(templates)
            
            # Populate variables
            phone = random.choice(camp["phones"])
            upi = random.choice(camp["upis"])
            domain = random.choice(camp["domains"])
            url = f"https://{domain}/login/verify?id={random.randint(1000, 9999)}"
            bank = random.choice(BANKS)
            courier = random.choice(COURIERS)
            acc = f"XX{random.randint(1000, 9999)}"
            parcel = f"IN{random.randint(100000, 999999)}P"
            
            content = template.format(
                bank=bank,
                acc=acc,
                url=url,
                phone=phone,
                upi=upi,
                courier=courier,
                parcel=parcel
            )
            
            timestamp = base_time + timedelta(days=random.randint(0, 30), hours=random.randint(0, 23), minutes=random.randint(0, 59))
            
            incident = {
                "incident_id": inc_id,
                "campaign_id": camp["campaign_id"],
                "campaign_name": camp["name"],
                "channel": random.choice(["sms", "whatsapp", "email"]),
                "language": lang,
                "raw_content": content,
                "timestamp": timestamp.isoformat(),
                "ground_truth": {
                    "is_malicious": True,
                    "campaign_id": camp["campaign_id"],
                    "impersonation_target": camp["target"],
                    "tactics": camp["tactics"],
                    "phone": phone,
                    "upi": upi,
                    "domain": domain,
                    "url": url,
                    "actor": camp["actor"],
                    "malware": camp["malware"]
                }
            }
            all_incidents.append(incident)
            inc_counter += 1

    # Add negative controls
    for neg in NEGATIVE_CONTROLS:
        timestamp = base_time + timedelta(days=random.randint(5, 25), hours=random.randint(1, 20))
        all_incidents.append({
            "incident_id": neg["incident_id"],
            "campaign_id": None,
            "campaign_name": None,
            "channel": neg["channel"],
            "language": neg["language"],
            "raw_content": neg["raw_content"],
            "timestamp": timestamp.isoformat(),
            "ground_truth": {
                "is_malicious": False,
                "campaign_id": None,
                "impersonation_target": "none",
                "tactics": [],
                "note": neg["note"]
            }
        })

    # Save to data directory
    output_path = DATA_DIR / "synthetic_incidents.json"
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(all_incidents, f, indent=2, ensure_ascii=False)

    campaigns_path = DATA_DIR / "synthetic_campaigns.json"
    with open(campaigns_path, "w", encoding="utf-8") as f:
        json.dump(CAMPAIGN_SPECS, f, indent=2, ensure_ascii=False)

    return len(all_incidents), len(CAMPAIGN_SPECS)


if __name__ == "__main__":
    n_inc, n_camp = generate_synthetic_dataset()
    print(f"Generated {n_inc} synthetic incidents across {n_camp} ground-truth campaigns.")
