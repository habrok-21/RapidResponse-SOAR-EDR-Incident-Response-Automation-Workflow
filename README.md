# RapidResponse-SOAR-EDR Incident Response Automation Workflow

An automated Security Operations Center (SOC) workflow designed to detect malicious activity, enrich incoming alerts with threat intelligence, and execute rapid incident response capabilities including automated mitigation and one click host isolation.

---

## 📌 Project Overview
Modern Security Operations Center (SOC) analysts face immense cognitive fatigue from continuous monitoring and massive log volumes. This project implements an automated **SOAR (Security Orchestration, Automation, and Response)** workflow paired with an **EDR (Endpoint Detection and Response)** platform to bridge the gap between real-time threat detection and rapid incident mitigation, even when analysts are away from their workstations.

---

## The Problem
* **Continuous Monitoring Fatigue:** Attackers do not operate on a schedule, and human analysts cannot monitor a SIEM or EDR console every single second. Critical alerts can easily be missed during shift handovers or off-hours.
* **Triage Bottlenecks:** Reviewing raw logs and manually checking external threat intelligence sources takes valuable time, allowing a threat to spread laterally across a network.
* **Mobility Constraints:** Traditional incident response heavily relies on an analyst being at their laptop, logged into a secure network, and manually navigating complex security consoles to contain a compromised host.

---

## The Solution
This project automates the entire detection, enrichment, and containment lifecycle:
1. **Automated Detection:** Leverages EDR telemetry combined with custom detection rules and the **Sigma** rule library to catch malicious behavior instantly.
2. **Instant, Mobile-Friendly Alerting:** Instead of forcing analysts to watch a console, the workflow pushes comprehensive alert data directly to **Slack** and **Email**. This allows the SOC team to receive structured, actionable details on their mobile devices or laptops.
3. **Automated Threat Intelligence:** The workflow automatically extracts destination IPs from detections and queries threat intelligence databases. If the IP reputation score exceeds high-confidence thresholds, the workflow triggers an immediate safety response.
4. **Dual-Mode Isolation:**
   * **Automated Isolation:** Automatically isolates the compromised host if high confidence threat intelligence thresholds are met.
   * **One-Click Manual Isolation:** Interactive alert blocks in Slack allow a mobile analyst to securely isolate a machine with a single tap, minimizing the Mean Time to Respond (MTTR).

---

## Automated Workflow Detail

### 1. Ingestion and Parsing (`retrieve_detections`)
The pipeline begins at the Webhook agent node, which listens continuously for raw telemetry events forwarded by LimaCharlie. Upon receiving the JSON payload, the engine runs variable parsing filters to extract critical incident context:
* Unique Endpoint Identifier (`routing/agent_id`)
* Local system context (`detect/req/identity/computer_name`, `detect/req/identity/username`)
* Network indicators (Target Destination IPs)

### 2. Threat Intel Enrichment
Before notifying the team, the engine strips target IP parameters out of the payload and performs an asynchronous lookup against the AbuseIPDB API. This step dynamically adds external context (such as the total abuse confidence score, ISP, and country of origin) to the incident timeline without human intervention.

### 3. Logical Evaluation (The Decision Matrix)
The workflow branches depending on the threat intelligence score:
* **High-Confidence Threat Loop:** If the AbuseIPDB score is strictly greater than **75%**, the workflow assumes a high-risk compromise scenario. It bypasses manual verification and immediately triggers a callback to LimaCharlie's isolation API to contain the machine instantly.
* **Standard Triage Loop:** If the score is below the strict threshold, it triggers the notification phase to enlist human evaluation.

### 4. Interactive Notification and Analyst Callback
The workflow constructs a rich text Markdown notification block layout and delivers it to Slack. Crucially, the "Isolate Host" button in Slack is built with an interactive payload block containing the specific `agent_id`. 

When an analyst taps the button from their laptop or mobile device:
1. Slack sends an outgoing callback POST request back to a dedicated webhook in Tines.
2. Tines verifies the response signature, extracts the `agent_id`, and passes an execution command to LimaCharlie.
3. LimaCharlie applies network isolation rules to the specific endpoint, preventing all lateral movement while preserving the sensor's connection for remote forensic collection.

## Deployment & Lab Setup

For detailed instructions on how to configure, build, and deploy this project, please refer to our dedicated guide:

**[Deployment and Setup Guide](deployment.md)**

## Project Evidence & Verifications
**[Demonstration Videos](project_evidence_verifications)**

1. Project Demo Video ~ demonstration_of_project.mp4

2. Isolation of User machine using Tines user_prompt (another way to isolate) ~ isolate_user_via_tines_user_prompt.mp4
