# Sigma Rule Tuning and Enrichment Guide

This guide covers the additional enrichment and tuning requirements for Rules 2, 4, and 5.

These rules depend on fields that may not exist directly in standard email gateway logs. The required values must be created through enrichment, parsing, directory integration, or derived-field processing before the rules can function as intended.

All rules should initially run in alert-only mode.

---

## Rule 2 — Newly Registered Domain with Phishing Keywords

### Detection Intent

Rule 2 detects external emails that combine:

- A recently registered sender domain
- Targeted phishing or business-lure language
- A link inside the message

The rule relies on multiple weak indicators becoming meaningful when correlated.

### Required Enrichment

#### `domain_age_days`

This field represents the number of days since the sender domain was registered.

Possible enrichment sources include:

- WHOIS or RDAP
- Domain intelligence providers
- Threat intelligence platforms
- Internal enrichment services

Example:

```yaml
domain_age_days: 12

The example rule uses:

domain_age_days|lt: 30

The 30-day threshold is a starting point and should be tuned based on your environment.

Additional Required Fields
contains_link

This field indicates whether the email body contains one or more links.

Example:

contains_link: true

Confirm whether your telemetry uses:

true
1

or another representation.

Common False Positives
New vendors
Startup companies
Recently rebranded organizations
New business domains
Legitimate first-contact emails
Newly launched customer or vendor portals
Recommended Tuning
Adjust the domain-age threshold
Allowlist approved new vendors
Tune phishing and business-lure keywords
Exclude internal domains
Correlate with sender reputation
Correlate with first-seen sender status
Add recipient sensitivity or department context
Recommended Starting Mode

Run in alert-only mode for approximately 60 days.

Rule 4 — Credential-Harvesting Infrastructure
Detection Intent

Rule 4 detects links pointing to possible credential-harvesting infrastructure by combining:

A lookalike domain
A recently issued TLS certificate
Login-page content discovered during sandbox analysis

The rule focuses on the infrastructure behind the email link rather than only the wording inside the message.

Required Enrichment
url_domain

This field contains the domain extracted from URLs found in the email body.

Example:

url_domain: yourdomain-sso-login.com

The extraction pipeline should:

Parse links from HTML and plain-text email bodies
Resolve shortened URLs when possible
Preserve the original URL
Record redirect destinations
Normalize domains before comparison
ssl_cert_age_days

This field represents the age of the TLS certificate used by the destination domain.

Possible sources include:

Certificate Transparency logs
crt.sh
TLS inspection services
Threat intelligence providers
Internal certificate-enrichment services

Example:

ssl_cert_age_days: 3

The example rule uses:

ssl_cert_age_days|lt: 7

A newly issued certificate is not automatically malicious. The value becomes meaningful when combined with the other rule conditions.

sandbox_page_content

This field contains text or structured indicators extracted after safely loading the destination page in a sandbox.

Possible sources include:

URLscan.io
VirusTotal
Internal URL sandboxing
Secure web gateways
Browser-isolation platforms

Example:

sandbox_page_content:
  - username
  - password
  - sign in
Lookalike-Domain Tuning

Replace the example domain patterns with variations relevant to your organization.

Example:

url_domain|contains:
  - yourdomain-sso
  - yourdomain-login
  - yourdomain-portal
  - yourd0main

Consider including:

Brand misspellings
Character substitutions
Hyphenated variants
Brand-plus-login combinations
SSO and portal naming patterns
Common homoglyph substitutions
Common False Positives
New internal portals
Approved vendor login pages
Newly deployed applications
Certificate renewals
New organizational subdomains
Approved authentication providers
Legitimate SaaS login pages
Recommended Tuning
Allowlist approved identity providers
Allowlist known SaaS login domains
Maintain organization-specific lookalike patterns
Validate sandbox parsing
Correlate with redirect chains
Exclude parked or unreachable domains
Correlate with domain age and reputation
Confirm the page contains actual credential-entry behavior
Recommended Starting Mode

Run in alert-only mode for approximately 30 days.

Rule 5 — Operational Stress Window Targeting
Detection Intent

Rule 5 detects urgent, link-bearing emails sent to operational teams during high-pressure business windows from low-reputation sender domains.

The rule combines:

Recipient-local operational time
Recipient department
Sender-domain reputation
Link presence
Urgent subject language
Required Enrichment
local_hour

This field represents the event time normalized to the recipient’s local office or timezone.

Do not use raw UTC unless all recipients operate in the same timezone.

Example:

local_hour: 7

Before deployment:

Normalize timestamps to the recipient’s office or timezone
Validate daylight-saving-time handling
Confirm the field is populated consistently
Define behavior for remote employees
Define behavior for users assigned to multiple offices
Test each region separately

Example operational windows:

local_hour:
  - 6
  - 7
  - 8
  - 14
  - 15
  - 22
  - 23
  - 0

These hours are examples only.

Replace them with stress windows observed in your environment, such as:

Shift changes
Production handoffs
Service-desk transitions
Overnight support periods
Finance close
Payroll processing
Executive travel windows
recipient_department

This field should be populated using directory or identity-provider data.

Possible sources include:

Active Directory
Microsoft Entra ID
Okta
HR systems
Identity governance platforms

Example:

recipient_department: Security Operations

Use the exact department values present in your environment.

Possible operational departments include:

recipient_department|contains:
  - Operations
  - Production
  - Logistics
  - Security Operations
  - Network Operations
  - Service Desk
  - Dispatch
  - Facilities
sender_domain_reputation_score

This field represents the reputation score assigned to the sender domain.

Possible sources include:

Threat intelligence providers
Email security vendors
Domain reputation services
Internal reputation systems

Example:

sender_domain_reputation_score: 24

The example rule uses:

sender_domain_reputation_score|lt: 50

Confirm the scoring direction used by your provider.

Some systems use:

Lower score = higher risk

Others use:

Higher score = higher risk

Do not deploy the rule until the scoring model is confirmed.

has_link

This field indicates whether the email contains a link.

Example:

has_link: true

Confirm whether your telemetry uses:

true
1

or another format.

Urgency-Language Tuning

Example subject keywords:

subject|contains:
  - urgent
  - immediate action
  - verify
  - reset
  - action required

Tune the list using language commonly observed in both legitimate and malicious communication in your environment.

Common False Positives
Legitimate IT notifications
Incident-response messages
Maintenance alerts
Payroll or HR communication
Vendor outage notifications
Emergency operational requests
Service-desk password-reset messages
Recommended Tuning
Define separate windows for each office or region
Use accurate directory department values
Allowlist approved senders
Correlate with first-seen sender status
Add sender-domain age
Add link reputation
Review urgency-language frequency
Analyze alerts by hour and department
Exclude expected internal notification systems
Recommended Starting Mode

Run in alert-only mode for approximately 90 days.

Example Field Mapping

The fields used in these rules are generic examples and may not match your telemetry schema.

Generic Field	Possible Mapped Field
domain_age_days	email.sender.domain_age_days
contains_link	email.has_url
url_domain	email.url.domain
ssl_cert_age_days	url.tls.certificate_age_days
sandbox_page_content	url.sandbox.page_content
local_hour	Derived recipient-local field
recipient_department	user.department
sender_domain_reputation_score	email.sender.domain_reputation
has_link	email.has_url
subject	email.subject

Successful Sigma conversion does not guarantee that these fields are mapped correctly.

Validation Checklist

Before deploying Rules 2, 4, or 5:

 Required enrichment fields are populated
 Field types are confirmed
 Boolean conventions are confirmed
 Field mappings are documented
 Timezone normalization is tested
 Daylight-saving behavior is validated
 Reputation-score direction is confirmed
 Historical telemetry is tested
 False positives are reviewed
 Exceptions are documented
 Converted SIEM query is reviewed
 Query performance is measured
 Alert ownership is defined
 Automated response is disabled initially
Recommended Rollout
Rule	Starting Mode	Suggested Tuning Period
Rule 2	Alert-only	Approximately 60 days
Rule 4	Alert-only	Approximately 30 days
Rule 5	Alert-only	Approximately 90 days

These periods are starting recommendations and will vary based on email volume, organizational complexity, and telemetry quality.

Final Guidance

These detections are sanitized, production-derived starting points.

They must be adapted to your environment before deployment.

A rule match should begin an investigation and should not automatically be treated as confirmed malicious activity.

Enrich → Detect → Investigate → Tune → Validate → Respond
