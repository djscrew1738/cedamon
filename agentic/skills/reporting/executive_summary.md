---
name: Executive Summary Writing
description: Writing concise, impactful executive summaries for penetration testing reports that communicate risk to non-technical stakeholders
---

# Executive Summary Writing

Pull this skill when compiling the final report and you need to write the executive summary section. This is the most-read part of any penetration test report — prioritize clarity, business impact, and actionable takeaways over technical detail.

## Purpose

The executive summary is the only section many stakeholders read. It must:
- Communicate the overall security posture in business terms
- Highlight the most critical risks and their potential business impact
- Provide clear direction on what needs to be fixed first
- Build trust through transparency and professional tone

## Template

```
## Executive Summary

[Organization] engaged RedAmon to conduct a penetration test of [scope]
from [start date] to [end date]. The assessment identified [X] findings:
[Y] Critical, [Z] High, [W] Medium, [V] Low, and [U] Informational.

### Key Strengths
- Specific controls that worked well (e.g., "Web application firewall
  effectively blocked automated scanning attempts")
- Areas where the target exceeded expectations

### Critical & High Risk Findings Summary
- Finding 1: One-sentence description + business impact
- Finding 2: One-sentence description + business impact
- Finding 3: One-sentence description + business impact

### Root Cause Themes
What patterns caused most findings (e.g., "Lack of input validation",
"Missing security patches", "Overly permissive network ACLs")

### Remediation Priorities
1. Most important fix — why it matters and expected effort
2. Second most important fix — why it matters and expected effort
3. Third most important fix — why it matters and expected effort

### Conclusion
One-paragraph bottom line: overall risk level, whether retesting is
recommended, and any strategic observations.
```

## Risk level statements

| Overall risk | When to use | Example language |
|-------------|-------------|-----------------|
| Critical | Multiple Critical findings, or a single Critical finding on a crown-jewel system | "The overall risk posture is Critical. An attacker could gain unrestricted access to the core production database with minimal effort." |
| High | Multiple High findings, or a single Critical with compensating controls | "The overall risk posture is High. While no single finding is Critical, the combination of identified weaknesses would allow a determined attacker to achieve persistent access." |
| Medium | Several Medium findings, no High/Critical | "The overall risk posture is Medium. The assessment identified several areas for improvement, though no immediate compromise was demonstrated." |
| Low | Only Low/Info findings | "The overall risk posture is Low. The tested environment demonstrates a mature security posture with only minor areas for improvement identified." |
| Mixed | Findings span the full range | Use the highest severity present with qualifiers: "While most findings are Low or Medium, the single High-severity SQL injection vulnerability in the customer-facing portal represents a significant risk that should be addressed urgently." |

## Writing for different audiences

### CISO / VP of Security
```
Focus: Risk posture, regulatory impact, resource requirements
Language: "The SQL injection vulnerability places customer PII at risk
of exposure, which may have GDPR implications with fines up to 4% of
global revenue. Recommend allocating development resources to implement
parameterized queries within the next sprint."
```

### Engineering Manager
```
Focus: Specific systems, remediation effort, prioritization
Language: "The payment processing API at /api/v2/payments/process
allows unauthenticated access to transaction histories. This affects
services A, B, and C. Estimated fix effort: 3-5 days including testing."
```

### Executive / Board Member
```
Focus: Business impact, competitive risk, customer trust
Language: "Our customer-facing application has a vulnerability that
could allow an attacker to access any customer's account without a
password. This type of issue erodes customer trust and could lead to
both customer churn and regulatory scrutiny."
```

## Common pitfalls

| Pitfall | Fix |
|---------|-----|
| Too technical | Replace "XSS via reflected unvalidated input in the search parameter" with "Attackers could inject malicious code into our website that would execute in visitors' browsers" |
| Too vague | Replace "Several high-risk issues were identified" with "The assessment identified 3 Critical and 5 High-severity vulnerabilities" |
| No business context | Replace "SQL injection in login" with "Attackers could bypass authentication on the customer portal, accessing any user account including administrator accounts" |
| Wall of text | Use bullet points, short paragraphs (2-3 sentences max), and clear section headers |
| No call to action | Every executive summary must state the single most important thing to fix first |

## Finding count summary table

```
┌─────────────────────┬──────────┐
│ Severity            │ Count    │
├─────────────────────┼──────────┤
│ Critical            │    2     │
│ High                │    5     │
│ Medium              │    8     │
│ Low                 │   12     │
│ Informational       │    6     │
├─────────────────────┼──────────┤
│ Total               │   33     │
│ ─────────────────── │          │
│ Retest Required     │   No     │
│ Overall Risk        │   High   │
└─────────────────────┴──────────┘
```

## Validation shape

An executive summary is complete when:
- [ ] Clearly states the overall risk level
- [ ] Includes finding counts by severity
- [ ] Describes the top 3-5 most important findings in business terms
- [ ] Identifies root cause themes
- [ ] Provides prioritized remediation guidance
- [ ] Written so a non-technical reader understands the risks
- [ ] Fits on 1-2 pages maximum

## Hand-off

- After writing the executive summary: `-> /skill/reporting/finding_writing` for detailed finding descriptions
- For remediation planning: Compile the prioritized remediation list from findings data
- For presentation: Create a slide deck from the executive summary and top findings

## Pro tips

- **Lead with the bad news**: Put the most critical findings first. Don't bury the headline.
- **Strengths matter**: Including a "Key Strengths" section shows you're fair and builds credibility with the development team.
- **One report, one voice**: The executive summary should be written last, after all findings are finalized, so it accurately reflects the overall assessment.
- **Risks, not vulnerabilities**: Frame everything as business risk. A "stored XSS" becomes "an attacker could impersonate any user and perform actions on their behalf without authorization."
- **Trending**: If this is a recurring test, include trend data: "This assessment identified 33 findings, compared to 42 in the previous test — a 21% reduction, indicating effective remediation of previously identified issues."
