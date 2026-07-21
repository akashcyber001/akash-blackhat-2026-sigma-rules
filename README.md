# Detection Engineering Beyond the Inbox

### Black Hat USA 2026 — Sigma Detection Rules

> **Presented by Akash Parasumanna Sridhar**  
> Cybersecurity Professional, Campbell Clinic  
> Black Hat USA 2026 | Mandalay Bay, Las Vegas | August 5, 2026

---

## The Problem

In our 18-month production deployment processing more than 2.3 million emails per day, gateway-only controls detected approximately **37% of the targeted phishing cases analyzed**.

The remaining attacks did not necessarily get through because the gateway was broken. Many appeared technically valid or blended into operational workflows the organization had to keep open.

Email gateways remain an essential control point, but gateway verdicts alone do not always capture identity, timing, recipient behavior, workflow patterns, infrastructure context, or conversation history.

This repository contains five sanitized Sigma rules derived from production-tested detection logic.

The broader detection engineering program—combining gateway telemetry, SIEM correlation, tuned detections, enrichment, analyst feedback, and response workflows—improved combined efficacy to **94%** and reduced mean time to detect from **4.2 hours to 12 minutes**.

---

## The Rules

| # | Rule | MITRE ATT&CK | Level | Observed FP Rate |
|---|------|--------------|-------|------------------|
| 1 | [Executive Display Name Impersonation](rules/rule1_display_name_impersonation.yml) | T1566.002, T1598.003 | High | 2.3% after tuning |
| 2 | [Newly Registered Domain + Phishing Keywords](rules/rule2_newly_registered_domain.yml) | T1566.002 | High | 8.1% after tuning |
| 3 | [Authentication Failure from Trusted External Domain](rules/rule3_auth_failure_trusted_domain.yml) | T1566, T1078 | Medium | Environment-dependent |
| 4 | [Credential Harvesting Infrastructure](rules/rule4_credential_harvesting.yml) | T1566.002, T1598 | High | 3.2% after tuning |
| 5 | [Operational Stress Window Targeting](rules/rule5_operational_stress_windows.yml) | T1566.002 | Medium | Environment-dependent |

---

## Key Findings

- **63%** of targeted phishing cases in the analyzed deployment were not detected by gateway-only controls
- **78%** of observed credential-harvesting activity occurred during operational transition windows
- **34%** of observed executive impersonation activity involved trusted or previously accepted external-domain relationships
- **$2.3 million** in attempted fraud was prevented after implementation
- **200+ accounts** were protected from compromise

These findings reflect the analyzed production environment and should not be interpreted as universal industry benchmarks.

---

## Before You Deploy

These rules are sanitized starting points and require customization before use.

Replace the following placeholders:

| Placeholder | Replace With |
|-------------|--------------|
| `yourdomain.com` | Your organization's email domain |
| `trusted-partner.com` | Your approved vendor and partner domains |
| `yourdomain-sso` | Your SSO-related domain patterns |
| `yourdomain-portal` | Your portal-related domain patterns |
| `recipient_department` values | Your directory or identity-provider department values |

### Rule 5 Requirements

Rule 5 uses recipient-local operational time rather than raw UTC.

Before deployment:

- Confirm timestamps are normalized to the recipient's office or timezone
- Validate daylight-saving handling
- Confirm the field used for local time is populated consistently
- Confirm the boolean convention for fields such as `has_link`
- Tune operational windows to match your environment

Rules 2, 4, and 5 also require enrichment data. See the [Tuning Guide](tuning/TUNING_GUIDE.md) for implementation details.

---

## SIEM Compatibility

These rules use Sigma format with a `category: email` log source.

They may be converted for supported backends using `sigma-cli`, including environments such as:

- Elastic
- OpenSearch
- Splunk
- Microsoft Sentinel
- QRadar
- Chronicle
- Datadog

Successful conversion does not guarantee production readiness.

Deployment still requires:

- Field mapping
- Backend testing
- Telemetry validation
- Enrichment validation
- Query review
- Performance testing
- False-positive tuning

Install and use [sigma-cli](https://github.com/SigmaHQ/sigma-cli) with the appropriate backend plugin.

Example:

```bash
sigma convert -t splunk rules/rule1_display_name_impersonation.yml
sigma convert -t elasticsearch rules/rule1_display_name_impersonation.yml
sigma convert -t sentinel rules/rule1_display_name_impersonation.yml
```

---

## Deployment Recommendation

Start with **Rules 1 and 4** in alert-only mode. In the analyzed environment, these had the lowest observed false-positive rates after tuning. Budget time for a tuning period before enabling any automated quarantine or blocking action — the duration required will vary by environment and email volume.

| Rule | Observed FP Rate | Approximate Tuning Period |
|------|-------------------|---------------------------|
| Rule 1 — Display Name | 2.3% after tuning | ~30 days |
| Rule 2 — New Domain | 8.1% after tuning | ~60 days |
| Rule 3 — Auth Failure | Environment-dependent | ~45 days |
| Rule 4 — Credential Harvesting | 3.2% after tuning | ~30 days |
| Rule 5 — Stress Window | Environment-dependent | ~90 days |

These figures reflect one production deployment and are provided as a reference point, not a guarantee of performance in a different environment.

---

## Enrichment Requirements

| Rule | Enriched Field | Suggested Source |
|------|-----------------|-------------------|
| Rule 2 | `domain_age_days` | WHOIS lookup at ingest (Logstash, Cribl, or equivalent) |
| Rule 4 | `ssl_cert_age_days` | Certificate transparency log query (e.g., crt.sh) at URL extraction |
| Rule 4 | `sandbox_page_content` | URL sandbox or scanning service (e.g., URLscan.io, VirusTotal, or internal sandbox) |
| Rule 4 | `url_domain` | Extracted from links in email body at ingest |
| Rule 5 | `local_hour` | Timestamp normalized to recipient timezone/office at ingest — not raw UTC |
| Rule 5 | `recipient_department` | Directory or identity-provider integration (AD, Azure AD, Okta) |
| Rule 5 | `sender_domain_reputation_score` | Threat intelligence feed integration (0–100 scale, lower indicates higher risk) |
| Rule 5 | `has_link` | Boolean field — confirm your pipeline's convention (true/false vs 1/0) before deploying |

Without these fields populated correctly, the affected rules will not fire as intended, or may fire incorrectly.

---

## Status

All rules are marked `status: experimental`, consistent with SigmaHQ convention for community-contributed detections that have not undergone formal cross-organization validation.

These rules should be run in alert-only mode and validated against your own telemetry before any automated response action is enabled.

---

## License

MIT License. These rules may be used, modified, and redistributed with attribution. No warranty is provided regarding detection efficacy in any environment other than the one described in this repository.

---

## About the Author

**Akash Parasumanna Sridhar**
Cybersecurity Professional, Campbell Clinic

Detection engineering · Incident response · Security automation
SIEM-driven detections · SOAR workflows · Email security monitoring

Open to conversations about detection engineering, security operations, and blue team.

[LinkedIn](https://www.linkedin.com/in/akash-parasumanna-sridhar/) · [Email](akashpsusa@gmail.com)

---

*Presented at Black Hat USA 2026. Findings are based on one production environment and are provided for reference, not as a general industry benchmark. All data has been sanitized and de-identified.*
