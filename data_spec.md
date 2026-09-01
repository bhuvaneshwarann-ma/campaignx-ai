# ANTIGRAVITY — MASTER BUILD PROMPT

# CAMPAIGNX AI — UNIFIED THREAT & SCAM INTELLIGENCE PLATFORM

You are the lead software architect, senior full-stack developer, cybersecurity engineer, AI/ML engineer, threat-intelligence analyst, UI/UX designer, DevOps engineer, and QA engineer for this project.

Your task is to BUILD the complete application described below.

Do not merely create a prototype UI.

Do not create fake buttons.

Do not create static mock dashboards pretending to be functional.

Build a working end-to-end application with a real backend, database, intelligence pipeline, AI layer, graph engine, evidence system, security layer, offline mode, tests, and polished frontend.

The product must be original.

Use the investigation concepts of modern threat-intelligence platforms such as IOC pivoting, relationship graphs, malware intelligence, threat actors and ATT&CK as inspiration.

Use the supplied ScamTrap architecture as inspiration for scam DNA, entity resolution, campaign detection, provenance, evidence and offline operation.

DO NOT copy any proprietary code, branding, logo, exact UI, text, or implementation from ThreatFusionAI or any other product.

============================================================

# 1. PRODUCT NAME

============================================================

CAMPAIGNX AI

Tagline:

"From Indicators and Messages to the Campaign Behind the Threat."

Core mission:

Build an evidence-driven threat intelligence platform that allows analysts to start with either:

A. A technical indicator

OR

B. A suspicious scam communication

and discover the infrastructure, entities, relationships, campaigns, malware, threat actors and ATT&CK techniques associated with it.

============================================================

# 2. CORE PRODUCT IDEA

============================================================

The platform must answer:

"What threat or scam campaign is behind this evidence?"

There are TWO primary investigation modes.

MODE A — THREAT INTELLIGENCE

Input:

* IPv4
* IPv6
* MD5
* SHA1
* SHA256
* Domain
* URL
* CVE
* Email
* Phone
* UPI

MODE B — SCAM INTELLIGENCE

Input:

* SMS
* WhatsApp text
* Email
* copied conversation
* voice transcript
* multilingual scam message

Both modes eventually enter the same correlation system.

============================================================

# 3. END-TO-END PIPELINE

============================================================

Implement this complete pipeline:

USER INPUT
↓
INPUT TYPE DETECTION
↓
NORMALIZATION
↓
INTELLIGENCE EXTRACTION
↓
SCAM DNA / IOC INTELLIGENCE
↓
ENTITY RESOLUTION
↓
EXTERNAL THREAT INTELLIGENCE
↓
ML CANDIDATE GENERATION
↓
DETERMINISTIC VERIFICATION
↓
EVIDENCE CREATION
↓
RELATIONSHIP GRAPH
↓
CAMPAIGN DETECTION
↓
MALWARE / ACTOR / ATT&CK CORRELATION
↓
RISK ENGINE
↓
AI INVESTIGATOR
↓
ANALYST DECISION
↓
REPORT

Never skip the evidence and verification layers.

============================================================

# 4. TECHNOLOGY STACK

============================================================

Frontend:

* React
* TypeScript
* Vite
* Tailwind CSS
* shadcn/ui
* React Flow
* Recharts
* Lucide icons
* TanStack Query
* Zustand

Backend:

* Python 3.11+
* FastAPI
* Pydantic v2
* SQLAlchemy
* PostgreSQL
* pgvector
* Redis

AI:

* Google Gemini
* Grok
* OpenRouter

ML:

* scikit-learn
* Sentence Transformers
* NetworkX

Infrastructure:

* Docker
* Docker Compose

Testing:

* Pytest
* Playwright

============================================================

# 5. PROJECT STRUCTURE

============================================================

Create:

campaignx-ai/

```
frontend/
backend/
data/
tests/
docs/
scripts/
docker/

.env.example
docker-compose.yml
README.md
```

Backend:

backend/app/

```
api/
core/
models/
schemas/
services/
providers/
ai/
ml/
correlation/
graph/
campaigns/
evidence/
attack/
reports/
auth/
database/
```

Frontend:

frontend/src/

```
components/
pages/
layouts/
hooks/
services/
stores/
types/
lib/
```

============================================================

# 6. DATABASE

============================================================

Use PostgreSQL as the primary database.

Create these models:

User
Incident
ScamDNA
Entity
EntityMention
Relationship
Campaign
Evidence
RiskAssessment
Observation
ThreatActor
MalwareFamily
AttackTechnique
Investigation
AIReport
AuditLog

Relationships:

Incident
↓
EntityMention
↓
Entity

Incident
↓
ScamDNA

Incident
↓
Relationship
↓
Evidence

Campaign
↓
Incidents
↓
Entities
↓
Relationships
↓
Evidence

Use migrations.

Create seed scripts.

Allow SQLite fallback for simple local development if PostgreSQL is unavailable.

============================================================

# 7. UNIVERSAL SEARCH

============================================================

Create one central investigation search bar.

Placeholder:

"Search an IP, hash, domain, URL, CVE, email, phone, UPI or paste a suspicious message..."

Automatically detect:

HASH
IP
DOMAIN
URL
CVE
EMAIL
PHONE
UPI
TEXT
TRANSCRIPT

Examples:

8.8.8.8
→ IP investigation

CVE-2025-XXXX
→ CVE investigation

SHA256
→ Malware investigation

Suspicious SMS
→ Scam investigation

============================================================

# 8. IOC INTELLIGENCE

============================================================

Create a provider abstraction.

Interface:

ThreatIntelProvider

Methods:

lookup_hash()
lookup_ip()
lookup_domain()
lookup_url()
lookup_cve()
lookup_email()
lookup_phone()

Create providers where APIs are available:

* ThreatFusionAI
* VirusTotal
* AbuseIPDB
* AlienVault OTX
* URLhaus
* MalwareBazaar
* NVD
* CISA KEV
* MITRE ATT&CK
* WHOIS/RDAP

Important:

Do not hardcode fake results.

If an API key is missing:

show:

NOT CONFIGURED

If provider is unavailable:

show:

OFFLINE / DEGRADED

Never pretend that unavailable intelligence is real.

============================================================

# 9. THREATFUSION-STYLE PROVIDER

============================================================

Implement ThreatFusionAI as ONE provider, not as the foundation of the entire application.

Use:

THREATFUSION_API_KEY=

Base API:

https://api.threatfusionai.com

Use only the official documented API contract.

Never expose the API key to the frontend.

Normalize provider responses into internal CampaignX schemas.

Handle:

200
202
400
401
404
429
500

Use:

timeouts
retry limits
circuit breaker
error handling

============================================================

# 10. SCAM INGESTION

============================================================

Create an incident submission page.

Allow:

* paste text
* email text
* SMS
* WhatsApp conversation
* voice transcript

Fields:

incident_id
channel
timestamp
language
raw_content
source
tags

Treat ALL submitted content as untrusted.

============================================================

# 11. MULTILINGUAL SCAM ANALYSIS

============================================================

Support:

English
Hindi
Hinglish
Tamil
Tanglish

Automatically detect language.

Preserve original content.

Create normalized semantic representation.

Do not translate away the original evidence.

============================================================

# 12. SCAM DNA

============================================================

Create a strict Pydantic ScamDNA schema.

Fields:

language
channel
impersonation_target
impersonation_target_detail
urgency
fear
authority_pressure
credential_request
payment_request
payment_method
requested_action
social_engineering_tactics
target_type
script_features
infrastructure_indicators
phone_numbers
upi_ids
urls
domains
emails
extraction_confidence

Allowed impersonation targets:

bank
government_tax
law_enforcement
telecom
delivery_courier
family_member
employer
tech_support
other

Allowed tactics:

urgency_pressure
authority_impersonation
fear_induction
artificial_scarcity
trust_building
isolation_tactic
credential_harvesting
payment_redirection

Allowed payment methods:

upi
bank_transfer
gift_card
crypto
cash_pickup
wallet_app
other

Do not allow the LLM to invent arbitrary taxonomy labels.

============================================================

# 13. ENTITY RESOLUTION

============================================================

Extract and normalize:

PHONE
UPI
EMAIL
URL
DOMAIN
IP
HASH
CVE

Example:

+91 98765 43210

becomes:

+919876543210

Normalize:

domain case
URL structure
query parameters where appropriate
UPI casing
phone format
email casing

Create canonical entities.

============================================================

# 14. CORRELATION ENGINE

============================================================

This is one of the most important components.

Use HYBRID CORRELATION.

Stage 1:

ML/AI generates candidate relationships.

Features:

* behavioral similarity
* embedding similarity
* temporal proximity
* tactic overlap
* script similarity
* infrastructure overlap

Output:

relationship_probability

Stage 2:

Deterministic verification.

Check:

same phone
same UPI
same domain
same URL
same email
same IP
same malware
same infrastructure
strong behavioral overlap
temporal relationship

Then calculate:

relationship_confidence

Never expose raw ML probability as verified intelligence.

============================================================

# 15. FALSE POSITIVE PROTECTION

============================================================

This is mandatory.

Do NOT create a campaign merely because two messages contain words like:

KYC
OTP
bank
urgent
account

Require meaningful corroboration.

For example:

Incident A:

KYC
bank
urgent

Incident B:

KYC
bank
urgent

But:

different phone
different UPI
different domain
different infrastructure

Result:

RELATIONSHIP REJECTED

The UI must explain:

"Generic behavioral similarity was insufficient to establish campaign membership."

============================================================

# 16. EVIDENCE MODEL

============================================================

Create canonical Evidence objects.

Fields:

claim
type
source
confidence
supporting_incident_ids
supporting_entity_ids
supporting_relationship_ids
scoring_factors
timestamp

Types:

OBSERVED
INFERRED
PREDICTED

Definitions:

OBSERVED:

Directly observed evidence.

INFERRED:

Derived through extraction or correlation.

PREDICTED:

ML hypothesis before verification.

Never present PREDICTED as confirmed.

============================================================

# 17. CONFIDENCE NAMESPACES

============================================================

Never use a generic confidence variable.

Use:

extraction_confidence
resolution_confidence
relationship_probability
relationship_confidence
campaign_confidence

The UI should explain what each confidence means.

============================================================

# 18. CAMPAIGN ENGINE

============================================================

Create:

Campaign

Fields:

campaign_id
name
status
first_seen
last_seen
incident_count
entity_count
risk_score
campaign_confidence
evidence

Statuses:

EMERGING
ACTIVE
MONITORED
INACTIVE
DISMISSED

Campaign detection should use:

shared infrastructure
verified relationships
behavioral similarity
temporal proximity
relationship density

Do not create campaigns from text similarity alone.

============================================================

# 19. EMERGING CAMPAIGN DETECTION

============================================================

Create real-time/dynamic campaign monitoring.

Example:

Incident 1
Incident 2
Incident 3
Incident 4

same:

UPI
phone
domain

and similar behavior.

Generate:

EMERGING CAMPAIGN DETECTED

Show:

Campaign ID
Incident count
Shared infrastructure
Behavioral overlap
First seen
Last seen
Risk
Campaign confidence

============================================================

# 20. THREAT GRAPH

============================================================

Backend:

NetworkX

Frontend:

React Flow

Node types:

Incident
Phone
UPI
Email
URL
Domain
IP
Hash
CVE
Malware
Threat Actor
Campaign
ATT&CK Technique

Relationship types:

USES_PHONE
USES_UPI
USES_EMAIL
USES_URL
USES_DOMAIN
RESOLVES_TO
ASSOCIATED_WITH
SIMILAR_TO
MEMBER_OF
USES_MALWARE
USES_TECHNIQUE
ATTRIBUTED_TO
EXPLOITS

Every important relationship must have evidence.

============================================================

# 21. GRAPH EXPERIENCE

============================================================

Implement:

zoom
pan
fit
search
filter
expand
collapse
focus
hide node types
timeline filter
depth control

Investigation depth:

1
2
3
4
5

Create:

LITE INVESTIGATION

and:

DEEP INVESTIGATION

Lite:

direct relationships.

Deep:

multi-hop relationships.

Prevent infinite graph expansion.

============================================================

# 22. MALWARE INTELLIGENCE

============================================================

For hashes show:

MD5
SHA1
SHA256
file type
file size
detections
malware family
behavior
extracted IOCs
domains
IPs
URLs
ATT&CK techniques
campaigns
threat actors

Every major result must have source/evidence information.

============================================================

# 23. THREAT ACTOR INTELLIGENCE

============================================================

Display:

name
aliases
associated malware
campaigns
infrastructure
techniques
evidence

Attribution levels:

CONFIRMED
STRONGLY ASSOCIATED
POSSIBLE MATCH
WEAK MATCH
UNKNOWN

Never claim attribution without evidence.

============================================================

# 24. MITRE ATT&CK

============================================================

Create an ATT&CK explorer.

Show:

tactics
techniques
sub-techniques

For investigations:

OBSERVED
INFERRED
UNKNOWN

Each technique must show:

technique ID
name
evidence
source
related malware
campaign
actor

Never assign ATT&CK techniques solely because an AI model guessed them.

============================================================

# 25. CVE INTELLIGENCE

============================================================

For CVEs show:

CVE ID
CVSS
EPSS
CISA KEV
affected products
description
references
exploit status
related malware
campaigns
actors

Use authoritative data where configured.

============================================================

# 26. RISK ENGINE

============================================================

Risk must be calculated by backend logic.

Factors can include:

malicious verdicts
provider agreement
known malware
malicious infrastructure
campaign membership
ATT&CK evidence
CISA KEV
EPSS
recency
abuse reports
actor relationship

Return:

risk_score
severity
risk_factors
evidence

The LLM must never invent risk scores.

============================================================

# 27. AI INVESTIGATOR

============================================================

Create:

CampaignX Investigator

Providers:

Gemini
Grok
OpenRouter
MockLLM

Architecture:

AIProvider

```
GeminiProvider
GrokProvider
OpenRouterProvider
MockLLMProvider
```

Fallback:

Gemini
→ OpenRouter
→ Grok
→ Mock

AI receives verified investigation context.

AI must NOT independently invent intelligence.

System instruction:

"Use only supplied evidence. Clearly distinguish observed, inferred and predicted information. If evidence is insufficient, say so."

Supported questions:

Why are these incidents connected?

What makes this campaign suspicious?

What infrastructure is reused?

What should I investigate next?

Which ATT&CK techniques are supported by evidence?

What evidence supports this relationship?

Which IOC should I pivot to next?

============================================================

# 28. AI RESPONSE FORMAT

============================================================

AI output must contain:

SUMMARY

EVIDENCE

ANALYSIS

CONFIDENCE

LIMITATIONS

RECOMMENDED NEXT STEPS

Example:

SUMMARY:

The incidents appear connected.

EVIDENCE:

Shared UPI identifier.

Supporting incidents:

INC-001
INC-007
INC-013

ANALYSIS:

The shared infrastructure and verified behavioral overlap support campaign membership.

LIMITATIONS:

No direct threat-actor attribution was established.

NEXT STEPS:

Investigate the associated domain and IP infrastructure.

============================================================

# 29. OFFLINE MODE

============================================================

The application MUST work without external APIs.

Environment:

MODE=offline

Offline mode supports:

incident ingestion
Scam DNA
entity resolution
correlation
campaign detection
graph
risk engine
evidence
AI mock
reports
demo data

Create deterministic mock providers.

UI must clearly display:

OFFLINE MODE

Do not silently use fake data.

============================================================

# 30. SYNTHETIC DATASET

============================================================

Create deterministic demo data.

Generate:

200–500 incidents

10–20 campaigns

multiple languages:

English
Hindi
Hinglish
Tamil
Tanglish

Include:

shared phones
shared UPI IDs
shared domains
shared URLs
shared infrastructure
different unrelated incidents

Create ground truth.

Include negative controls specifically designed to test false campaign detection.

============================================================

# 31. DEMO DATA EXAMPLE

============================================================

CAMPAIGN A:

Phone A
UPI A
Domain A
URL A

Incidents:

INC-001
INC-002
INC-003
INC-004

CAMPAIGN B:

Phone B
UPI B
Domain B

Incidents:

INC-005
INC-006
INC-007

NEGATIVE CONTROL:

INC-008

Contains:

KYC
bank
OTP
urgent

but has:

different phone
different UPI
different domain
different infrastructure

The engine must reject INC-008 from Campaign A.

============================================================

# 32. SOC DASHBOARD

============================================================

Build a premium SOC dashboard.

Cards:

Active Campaigns
Emerging Campaigns
Critical IOCs
Incidents
Threat Actors
Malware Families
ATT&CK Techniques
Provider Health

Charts:

Incident volume
Risk distribution
Campaign growth
IOC types
Top tactics
Infrastructure
Campaign timeline

All values must come from backend data.

If database is empty:

"No intelligence collected yet."

============================================================

# 33. INVESTIGATION CONSOLE

============================================================

Desktop layout:

LEFT:

Navigation sidebar

CENTER:

Investigation workspace

RIGHT:

AI Investigator

BOTTOM:

Evidence timeline

Header:

Investigation ID
Indicator/Incident
Risk
Confidence
Status

Tabs:

Overview
Evidence
Scam DNA
Relationships
Graph
Malware
Threat Actors
ATT&CK
Campaign
Timeline
AI Analysis
Raw Data

============================================================

# 34. EVIDENCE UI

============================================================

Every major finding needs:

VIEW EVIDENCE

Clicking opens an Evidence Drawer.

Show:

Claim
Type
Source
Confidence
Supporting incidents
Supporting entities
Supporting relationships
Timestamp
Scoring factors

Example:

WHY CONNECTED?

OBSERVED:

Same UPI identifier.

Supporting:

INC-001
INC-007

Source:

Entity Resolver

Confidence:

0.94

============================================================

# 35. THREAT HUNTING

============================================================

Create:

LITE HUNT

DEEP HUNT

Lite:

IOC
↓
Direct relationships

Deep:

IOC
↓
Domain
↓
IP
↓
URL
↓
Hash
↓
Malware
↓
Actor
↓
Campaign

Depth:

1–5

Allow filters.

============================================================

# 36. PRIVACY

============================================================

PII must be protected.

Never log raw:

phone
UPI
email
sensitive message content

Use:

HMAC-SHA256
tokenization
masking

Example:

+919876543210

may appear in logs as:

PHONE_7F3A92

But analysts with permission can view the original value inside the investigation interface.

============================================================

# 37. SECURITY

============================================================

Implement:

JWT authentication
RBAC
secure password hashing
rate limiting
CORS
input validation
prompt injection defense
SSRF protection
URL validation
audit logging
secret management
provider timeout
retry limits
circuit breaker

Never execute:

malware
uploaded executables
user-submitted URLs

Never automatically visit suspicious URLs.

============================================================

# 38. FRONTEND ROUTES

============================================================

/

Landing page

/dashboard

Main SOC dashboard

/investigate

Universal investigation

/investigate/:id

Investigation workspace

/incidents

Incident list

/incidents/:id

Incident analysis

/campaigns

Campaign list

/campaigns/:id

Campaign investigation

/graph

Threat graph

/hunting

Threat hunting

/malware

Malware intelligence

/threat-actors

Threat actor intelligence

/attack

MITRE ATT&CK

/cves

CVE intelligence

/reports

Reports

/history

Investigation history

/settings

Settings

/admin

Admin

============================================================

# 39. LANDING PAGE

============================================================

Hero:

UNDERSTAND THE CAMPAIGN
BEHIND THE INDICATOR.

Subtitle:

"Connect suspicious indicators, scam behavior, infrastructure, malware and attacker techniques into one evidence-driven investigation."

Main search:

"Paste an IOC or suspicious message..."

Buttons:

START INVESTIGATION

EXPLORE DEMO

Features:

IOC Intelligence
Scam DNA
Campaign Detection
Threat Graph
ATT&CK Mapping
AI Investigator

============================================================

# 40. UI DESIGN

============================================================

Design a premium cybersecurity SOC interface.

Style:

dark
professional
technical
high-density
minimal
modern

Use:

dark charcoal panels
subtle borders
cyan/blue/purple accents
green/yellow/orange/red risk states

Use monospace typography for:

hashes
IPs
domains
URLs
CVE IDs
technical identifiers

Avoid excessive neon.

Avoid generic AI-dashboard aesthetics.

The interface should feel like a real SOC analyst platform.

============================================================

# 41. CAMPAIGN PAGE

============================================================

Example:

EMERGING CAMPAIGN

CAM-017

Bank KYC Redirection Campaign

Confidence:

92%

Risk:

CRITICAL

Incidents:

14

Entities:

21

Show:

Campaign timeline
Graph
Shared infrastructure
Scam DNA
Evidence
ATT&CK
Malware
Threat actors
AI analysis

Create:

WHY THIS IS A CAMPAIGN

✓ Shared UPI
✓ Shared phone
✓ Shared domain
✓ Behavioral overlap
✓ Temporal correlation

============================================================

# 42. REPORTING

============================================================

Generate:

PDF
JSON
CSV

Optional:

STIX 2.1

Report sections:

Executive Summary
Incident Details
IOC Details
Scam DNA
Risk Assessment
Evidence
Relationships
Campaign
Infrastructure
Malware
Threat Actors
MITRE ATT&CK
Timeline
Recommended Actions
Sources
Limitations

============================================================

# 43. API

============================================================

Implement:

POST /api/v1/incidents

GET /api/v1/incidents/{id}

GET /api/v1/incidents/{id}/dna

GET /api/v1/incidents/{id}/relationships

POST /api/v1/ioc/lookup

GET /api/v1/ioc/{id}

GET /api/v1/campaigns

GET /api/v1/campaigns/{id}

GET /api/v1/campaigns/{id}/graph

POST /api/v1/hunting

POST /api/v1/investigations/explain

POST /api/v1/ai/analyze

POST /api/v1/evaluation/run

GET /api/v1/health

Add:

/docs

/redoc

============================================================

# 44. PROVIDER HEALTH

============================================================

Display:

ThreatFusionAI
VirusTotal
AbuseIPDB
OTX
NVD
MITRE
Gemini
Grok
OpenRouter

Statuses:

ONLINE
DEGRADED
OFFLINE
NOT CONFIGURED

Never fake provider status.

============================================================

# 45. EVALUATION ENGINE

============================================================

Create:

/evaluation

Metrics:

Scam DNA precision
Scam DNA recall
Scam DNA F1
Entity resolution precision
Entity resolution recall
Campaign precision
Campaign recall
Campaign F1
False campaign rate
Relationship precision
Relationship recall
Latency
P50
P95
P99

Create:

docs/evaluation-report.md

Also create parameter sweeps for correlation thresholds.

Optimize:

F1

while minimizing:

False Campaign Rate

Document decisions in:

docs/decisions.md

============================================================

# 46. TESTING

============================================================

Create automated tests for:

IOC detection
Scam DNA extraction
language detection
entity normalization
PII masking
prompt injection
correlation
negative controls
campaign detection
risk calculation
evidence creation
AI restrictions
provider failure
offline mode
graph serialization
authentication
API endpoints

Frontend tests:

Playwright

Backend:

Pytest

============================================================

# 47. DEMO FLOW

============================================================

Create a one-click:

DEMO MODE

Scenario:

1. Submit English scam message.

2. Extract Scam DNA.

3. Submit Hinglish message.

4. Submit Tanglish message.

5. Resolve entities.

6. Find shared phone.

7. Find shared UPI.

8. Find shared domain.

9. Detect campaign.

10. Show campaign graph.

11. Show:

EMERGING CAMPAIGN DETECTED

12. Submit negative control.

13. Show:

RELATIONSHIP REJECTED

14. Click a graph relationship.

15. Open evidence drawer.

16. Ask AI:

"Why are these incidents connected?"

17. Show evidence-backed response.

18. Pivot from campaign to domain.

19. Pivot from domain to IP.

20. Pivot from IP to malware.

21. Show ATT&CK.

22. Ask AI:

"What should I investigate next?"

23. Generate report.

The entire flow must work offline.

============================================================

# 48. DEMO SCENARIO 2

============================================================

IOC investigation.

Input:

An example IP.

Pipeline:

IP detection

→ provider intelligence

→ reputation

→ DNS

→ domains

→ URLs

→ malware

→ threat actors

→ ATT&CK

→ campaign

→ graph

→ evidence

→ AI investigator

The user must be able to pivot from one node to another.

============================================================

# 49. CRITICAL AI RULES

============================================================

NEVER:

fabricate an IOC

fabricate a source

fabricate malware

fabricate threat actor attribution

fabricate ATT&CK mapping

fabricate campaign membership

fabricate risk score

fabricate provider results

fabricate evidence

fabricate numerical statistics

If evidence does not exist:

say:

"Insufficient evidence."

If provider is unavailable:

say:

"Provider unavailable."

If attribution is uncertain:

say:

"Possible association; attribution not confirmed."

============================================================

# 50. ENVIRONMENT

============================================================

Create:

.env.example

Variables:

DATABASE_URL=
REDIS_URL=
JWT_SECRET=

GEMINI_API_KEY=
GROK_API_KEY=
OPENROUTER_API_KEY=

THREATFUSION_API_KEY=
VIRUSTOTAL_API_KEY=
ABUSEIPDB_API_KEY=
OTX_API_KEY=

MODE=offline

Never commit real keys.

============================================================

# 51. DOCKER

============================================================

Create:

Dockerfile.backend
Dockerfile.frontend
docker-compose.yml

Services:

frontend
backend
postgres
redis

Application should start using:

docker compose up

============================================================

# 52. DOCUMENTATION

============================================================

Create:

README.md

docs/

architecture.md
api.md
database.md
security.md
ai.md
correlation.md
campaign-detection.md
evaluation-report.md
decisions.md
demo.md
deployment.md

README must explain:

What the application does
Architecture
Installation
Environment variables
Offline mode
API
Testing
Demo
Security
Limitations

============================================================

# 53. DEVELOPMENT ORDER

============================================================

DO NOT build everything at once.

Follow this order exactly.

PHASE 1

Project foundation

PHASE 2

Database

PHASE 3

Authentication/security foundation

PHASE 4

Synthetic dataset

PHASE 5

Scam DNA

PHASE 6

Entity resolution

PHASE 7

IOC provider framework

PHASE 8

Threat intelligence providers

PHASE 9

Correlation engine

PHASE 10

Evidence engine

PHASE 11

Campaign detection

PHASE 12

Graph engine

PHASE 13

Risk engine

PHASE 14

AI Investigator

PHASE 15

FastAPI API

PHASE 16

SOC frontend

PHASE 17

Threat hunting

PHASE 18

Reports

PHASE 19

Evaluation

PHASE 20

Security hardening

PHASE 21

Offline demo

PHASE 22

Final QA

============================================================

# 54. STRICT ANTIGRAVITY EXECUTION RULE

============================================================

Implement ONLY ONE PHASE at a time.

After each phase:

1. Write code.

2. Run backend tests.

3. Run frontend tests if applicable.

4. Run linting.

5. Run type checking.

6. Start application.

7. Verify API.

8. Verify database.

9. Verify UI.

10. Fix all errors.

Only then move to the next phase.

Do not skip failed tests.

Do not say "completed" if the application does not work.

============================================================

# 55. COMPLETION REPORT

============================================================

After every phase return:

PHASE X COMPLETION REPORT

Files created:
...

Files modified:
...

Features implemented:
...

Tests executed:
...

Tests passed:
...

Tests failed:
...

Security checks:
...

API checks:
...

Database checks:
...

Frontend checks:
...

Remaining issues:
...

Next phase:
...

============================================================

# 56. FINAL ACCEPTANCE CRITERIA

============================================================

The project is complete only when:

[ ] Frontend works

[ ] Backend works

[ ] Database works

[ ] Authentication works

[ ] IOC investigation works

[ ] Scam investigation works

[ ] Scam DNA works

[ ] Multilingual input works

[ ] Entity resolution works

[ ] IOC providers work when configured

[ ] Provider failures are handled

[ ] Correlation works

[ ] False positives are rejected

[ ] Campaign detection works

[ ] Emerging campaigns work

[ ] Graph works

[ ] Evidence works

[ ] Malware intelligence works

[ ] Threat actor intelligence works

[ ] ATT&CK works

[ ] Risk engine works

[ ] AI Investigator works

[ ] AI uses evidence only

[ ] Offline mode works

[ ] Synthetic dataset works

[ ] Reports work

[ ] Evaluation works

[ ] Security controls work

[ ] Automated tests pass

[ ] Docker deployment works

[ ] Documentation is complete

[ ] Hackathon demo works from start to finish

============================================================

# 57. FINAL PRODUCT EXPERIENCE

============================================================

The final product should feel like a unified cybersecurity investigation operating system.

The primary workflow is:

ONE IOC

OR

ONE SUSPICIOUS MESSAGE

↓

INTELLIGENCE

↓

SCAM DNA / IOC DATA

↓

ENTITY RESOLUTION

↓

CORRELATION

↓

VERIFICATION

↓

EVIDENCE

↓

GRAPH

↓

CAMPAIGN

↓

MALWARE / INFRASTRUCTURE / ACTOR

↓

MITRE ATT&CK

↓

RISK

↓

AI INVESTIGATOR

↓

RECOMMENDED NEXT PIVOT

↓

REPORT

The application must prioritize:

EVIDENCE

EXPLAINABILITY

SECURITY

PROVENANCE

DETERMINISTIC VERIFICATION

FALSE-POSITIVE DEFENSE

OFFLINE RELIABILITY

REAL FUNCTIONALITY

Do not build a fake AI showcase.

Build a working threat-intelligence and campaign-investigation platform.

START WITH PHASE 1 ONLY.

Do not implement Phase 2 until Phase 1 passes its tests.
