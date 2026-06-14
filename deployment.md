# Step-by-Step Lab Installation & Configuration Guide

This guide provides an end-to-end walkthrough for deploying the RapidResponse SOAR-EDR Incident Response Automation ecosystem. By the end of this guide, you will have a live environment capable of detecting malicious activities and the telemetry, enriching the threat indicators, alerting analysts via Slack/Email, generating Jira cases, and performing remote host isolation.

---

## Phase 1: Prerequisites

Before starting, ensure you have the following accounts and environments set up :

* **Target Endpoint:** A Windows 10/11 Virtual Machine or physical test host running in an isolated lab environment.
* **LimaCharlie Account:** Free-tier account with an organization created.
* **Tines Account:** Free Community Edition account.
* **Jira Cloud Instance:** Free Jira Service Desk or Jira Software cloud site.
* **Slack Workspace:** Slack workspace where you have administrative privileges to add webhooks / apps.
* **API Accounts:** Free accounts for **VirusTotal** and **AbuseIPDB** to retrieve API tokens.

---

## Phase 2: Telemetry Collection (EDR Setup)

### 1. Installing the LimaCharlie Sensor
1. Log into your **LimaCharlie Dashboard**.
2. Navigate to **Sensors** > **Installation Keys** and click **Create Installation Key**. Copy the generated key.
3. Go to **Sensor Downloads** and download the appropriate Windows installer executable (`hcp.exe`).
4. On your target Windows VM, open an Administrative Command Prompt and execute the following command to register the agent to your cloud instance:
   ```cmd
   hcp.exe -i YOUR_INSTALLATION_KEY
   ```
5. Navigate to Sensors > Manage Sensors in
LimaCharlie to confirm that your host (e.g.
jay-windows) is checking in with a green
online status indicator.

### 2. Configuring the D&R (Detection & Response) Rule
1. Go to Automation > D&R Rules > New Rule.
2. For Testing here we just set one rule for Credentials dumping tool LaZagne, u can create other rules like this or can use Sigma library on LimaCharlie.
3. Detect Section: Define what behavior trips
the alarm. Paste the following logic to look
for process creation matching the signature
parameters :
```yaml
events:
  - NEW_PROCESS
  - EXISTING_PROCESS
op: and
rules:
  - op: is windows
  - op: or
    rules:
    - case sensitive: false
      op: ends with
      path: event/FILE_PATH
      value: LaZagne.exe
    - case sensitive: false
      op: contains
      path: event/COMMAND_LINE
      value: LaZagne
    - case sensitive: false
      op: is
      path: event/HASH
      value: '3cc5ee93a9ba1fc57389705283b760c8bd61f35e9398bbfa3210e2becf6d4b05'
```
3. Response Section: Instruct LimaCharlie
what to do when a match is found. We tell it
to generate a detection report and forward
a webhook alert event upstream to Tines :
```yaml
- action: report
  metadata:
    author: Jay
    description: TEST - Detects Lazagne Usage
    falsepositives:
    - ToTheMoon
    level: high
    tags:
    - attack.credential_access
  name: HackTool - Lazagne
```

### 3. Create & Install Your Custom Slack app
Because Tines requires a secure authentication
bridge to interact with your specific workspace
you must create a custom application endpoint
in Slack.

1. Build the Slack App Frame
* Open a new browser tab and navigate to api.slack.com/apps.
* Click the green Create New App button.
* Choose the From scratch configuration Option.
* App Name: Tines-SOAR-Bot.
* Development Slack Workspace: Select your target workspace (e.g. SOAR-EDR) from the dropdown menu.
* Click Create App.

3. Set API Scopes (Permissions)
* In the left-hand sidebar menu under Features, click on OAuth & Permissions.
* Scroll all the way down to the Scopes block section.
* Locate the Bot Token Scopes table grid and click Add an OAuth Scope.
* Search for and add the chat:write scope permission.

5. Generate the Token & Invite the Bot
* Scroll back up to the top of the OAuth & Permissions page and click the green Install to Workspace button.
* Click Allow to approve the access requested by your app.Copy the long Bot User OAuth Token string (starts with xoxb-).
* Go to your Tines Dashboard, navigate to Credentials, click + New Credential, select Slack, and paste your xoxb- token into the OAuth Token field.
* Open your actual Slack desktop/web application, click inside the chat field for your #alerts channel, and run this command verbatim to invite your bot into the room:
```
/invite @Tines-SOAR-Bot
```
4. The "Isolate Machine" Interactive Button Logic
Step 1: Create the Slack Interactive Listener
Webhook in Tines
* Drag a brand new Webhook Action onto your Tines canvas.
* Name this block Slack Button Listener
* Copy the raw Webhook URL generated in its right-hand configuration panel. e.g. https://<your-tenant>[.tines.com/webhook/](https://tines.com/webhook/)

Step 2: Register the Interactivity URL in the Slack Developer Portal
* Go back to your application dashboard at api.slack.com/apps.
* On the left sidebar navigation, click on Interactivity & Shortcuts
* Toggle the Interactivity switch to ON.
* In the Request URL text box field, paste the exact Slack_Button _Listener Webhook URL you just copied from Tines.
* Click Save Changes at the bottom right.

### 3. The SOAR Automation Layer (Tines Configuration)
Instead of relying on a pre-packaged storyboard, this section details how to map out
the foundational pipeline components block by
block.

1. Create the Webhook Action (retrieve_detections) :
* Drag a Webhook Action onto your Tines canvas canvas and name it retrieve detections.
* This automatically generates a unique tracking URL. Copy this URL and paste it back into your LimaCharlie D&R response webhook rule block.

3. Dynamic JSON Path Mapping & Variables :
When parsing the complex data payload out of LimaCharlie to feed down-stream blocks (Slack messages action, Email), point your asset schemas explicitly to these parsed path strings :

* send Email action ~ 
```
<br>TITLE: <<retrieve_detections.body.cat>>
<br>DETECTION LINK: <<retrieve_detections.body.link>>
<br>TIME: <<retrieve_detections.body.detect.routing.event_time>>
<br>COMPUTER: <<retrieve_detections.body.detect.routing.hostname>>
<br>SOURCE IP: <<retrieve_detections.body.detect.routing.int_ip>>
<br>USERNAME: <<retrieve_detections.body.detect.event.USER_NAME>>
<br>FILEPATH: <<retrieve_detections.body.detect.event.FILE_PATH>>
<br>COMMAND LINE: <<retrieve_detections.body.detect.event.COMMAND_LINE>>
<br>SENSOR ID: <<retrieve_detections.body.detect.routing.sid>>
<br>VirusTotal Link: https://www.virustotal.com/gui/file/<<get_a_file_report.body.data.attributes.md5>>
```

* Slack alert message action ~
```
TITLE: <<retrieve_detections.body.cat>>
DETECTION LINK: <<retrieve_detections.body.link>>
TIME: <<retrieve_detections.body.detect.routing.event_time>>
COMPUTER: <<retrieve_detections.body.detect.routing.hostname>>
SOURCE IP: <<retrieve_detections.body.detect.routing.int_ip>>
USERNAME: <<retrieve_detections.body.detect.event.USER_NAME>>
FILEPATH: <<retrieve_detections.body.detect.event.FILE_PATH>>
COMMAND LINE: <<retrieve_detections.body.detect.event.COMMAND_LINE>>
SENSOR ID: <<retrieve_detections.body.detect.routing.sid>>
VirusTotal Link: https://www.virustotal.com/gui/file/<<virustotal_file_report.body.data.attributes.md5>>
```

* Slack AbuseIPDB message action ~
```
🚨 ALERT : Suspicious Activity Detected !
IP Address : <<check_ip_reputation.body.data.ipAddress>>
Country Code : <<check_ip_reputation.body.data.countryCode>>
ISP : <<check_ip_reputation.body.data.isp>>
Domain : <<check_ip_reputation.body.data.domain>>
isTor : <<check_ip_reputation.body.data.isTor>>
Usage Type : <<check_ip_reputation.body.data.usageType>>
Abuse Confidence Score : <<check_ip_reputation.body.data.abuseConfidenceScore>>%
```

* Slack Isolate button Action ~
```json
[
  {
    "type": "section",
    "text": {
      "type": "mrkdwn",
      "text": "*⚠️ Alert: Malicious Activity Detected!*\n*Sensor ID:* <<retrieve_detections.body.routing.sid>>"
    }
  },
  {
    "type": "actions",
    "elements": [
      {
        "type": "button",
        "text": {
          "type": "plain_text",
          "text": "🔴 Isolate Machine",
          "emoji": true
        },
        "style": "danger",
        "value": "<<retrieve_detections.body.routing.sid>>",
        "action_id": "isolate_button_click"
      }
    ]
  }
]
```


### 4. Jira Ticketing Configuration
1. HTTP Authentication Configuration ->
Drag an HTTP Request Action -> Set the tracking method configuration to POST -> point the target URI endpoint to your cloud instance location {https://YOUR-DOMAIN.atlassian.net/rest/api
/3/issue} -> Under Credentials select basic
authentication map against your admin email address.

2.Jira Cloud JSON Schema Payload Template
```json
{
  "fields": {
    "project": {
      "key": "KAN"
    },
    "summary": "EDR Alert: <<retrieve_detections.body.cat>> on <<retrieve_detections.body.detect.routing.hostname>>",
    "issuetype": {
      "name": "Task"
    },
    "description": {
      "type": "doc",
      "version": 1,
      "content": [
        {
          "type": "paragraph",
          "content": [
            {
              "type": "text",
              "text": "🚨 A detection alert was triggered.\n\nAlert Category: <<retrieve_detections.body.cat>>\nHost Name: <<retrieve_detections.body.detect.routing.hostname>>\nSensor ID: <<retrieve_detections.body.detect.routing.sid>>\nCommand Line: <<retrieve_detections.body.detect.event.COMMAND_LINE>>"
            }
          ]
        }
      ]
    }
  }
}
```

### 5. LimaCharlie user Isolation Action
1. By slack isolation button
* Drag an HTTP Request Action onto your canvas and place it as per the architecture.
* Name this block
* Configure the agent settings exactly like this URL:
```
https://api.limacharlie.io/v1/sensors<<JSON_PARSE(slack_button.body.payload).actions[0].value>>isolation
```
Method: POST

2. Isolation by user_prompt
* Drag an HTTP Request Action onto your canvas and place it as per the architecture.
* Name this block
* Configure the agent settings exactly like this URL:
```
https://limacharlie.io/v1/sensors/<sid>/isolation
```
Method: POST

### 6. For VirusTotal & AbuseIPDB action
* Drag an HTTP Request Action onto your canvas and place it as per the architecture.
* Name this block
* Setup Api key and their Credentials

---

## Phase 3 : Verification and Testing
1. Log onto your target Windows VM machine

2. Download or simulate the malicious runtime
tool. Launch a command prompt tool and execute :
```
LaZagne.exe all
```
3. Watch your automation work in real-time:
• LimaCharlie catches the telemetry and sends a webhook payload.
• Tines filters the data, updates threat metrics via AbuselPDB and Virus Total, and updates all active lines.
• A Slack Alert populates your incident monitoring channel with a custom layout card and action buttons.
• A Jira Ticket creates a work item for auditing verification tracking

4. From your Slack channel alert card, click Isolate Machine.

5. Back on your Windows VM terminal command line interface, try running a connectivity check:
```
ping google.com
```
The terminal will spit back a General failure exception message. Attempting to browse any external web space will result in network timeout execution failures, proving the host is completely contained !

• Visual Proof of Concept ~

### We can also isolate User through Tines user_prompt.
• Visual Proof of Concept ~

