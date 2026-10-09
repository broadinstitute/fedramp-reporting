# FedRAMP VER Phase 1: Triage Store and Report Generator

Date: 2026-10-09
Status: Draft for review

## 1. Goal

Generate FedRAMP CR26 Vulnerability Evaluation and Reporting JSON from triage decisions stored in cobbler. Phase 1 produces:

- Vulnerability Detail Report (VER-RPT-VDT) for non-accepted vulnerabilities.
- Accepted Vulnerability Info (VER-RPT-AVI) for accepted vulnerabilities.
- Historical VER Activity (VER-TFR-MRH). Class C providers should keep it updated at least every 14 days.

Phase 1 covers ZAP and CIS findings. Trivy is added when the partial Trivy importer is provided. Phase 2 (RAG-assisted suggested triage) is out of scope, but the data model reserves a field for it.

## 2. Background

- **cobbler** (https://github.com/broadinstitute/dsp-appsec-cobbler) is the team's vulnerability database. It is a work in progress and is not deployed. It is a Flask app on PostgreSQL with SQLAlchemy and Alembic migrations. Its hierarchy is Products → Services / Images / Infrastructure → Scans → Findings. `Finding` already holds a status enum, `status_modifier`, `jira_ticket`, severity, CWE, and CVE. It has importers for ZAP, CodeDx, and Azure CIS. It has no Trivy importer.
- **Current triage** lives in weekly Analysis documents in Google Drive, in spreadsheets, and in Jira. From this design forward, triage decisions are entered in cobbler. The Analysis documents remain the narrative record.
- **Schemas.** The three CR26 JSON schemas are dated 2026-06-24. They are published at fedramp.gov together with a common-definitions file that holds the `vulnerabilityDetail` and `acceptedVulnerabilityInfo` definitions. This repo vendors all four files so validation needs no network access.
- **Provider class.** Rev5 Class C. Class C makes VER-TFR-MRH a should-level requirement and adds the 5-day evaluation target (VER-TFR-EVU).
- **BOD 26-04** (issued 2026-06-10, supersedes BOD 19-02 and 22-01). Its Table 1 sets remediation timelines from four inputs: publicly exposed, in the KEV, automatable by an adversary, and technical impact. It covers federal civilian agencies, and it reaches contractors only where the procurement contract directs. For FedRAMP-certified cloud offerings, agencies work through the FedRAMP PMO. Applicability to this team is open (section 11).
- **Required judgments.** The CR26 rules require every detected vulnerability to be evaluated for internet reachability (VER-EVA-EIR), likely exploitability (VER-EVA-ELX), and potential agency impact as a PAIN N-rating (VER-EVA-EPA). Scanners do not produce these judgments. The schema does not require them, but this design treats them as required for every reported finding.

## 3. Components

### 3.1 cobbler (system of record)

- New `triage_assessment` and `pain_reduction_event` tables, with Alembic migrations.
- Endpoints to create and approve assessments, and to read a finding's assessments.
- Existing importers and the `Finding` model are unchanged, apart from the new relationships.

### 3.2 fedramp-reporting (report generator)

A Python CLI in this repo. It reads from cobbler's REST API, maps the data to CR26 structures, validates the output, and writes JSON files. Modules:

- `cobbler_client.py`: HTTP access to the cobbler endpoints.
- `mapping.py`: maps a finding and its current approved assessment to `vulnerabilityDetail` and `acceptedVulnerabilityInfo`.
- `reports.py`: builds the VDT, AVI, and optional MRH documents for a period.
- `validate.py`: validates against the vendored schemas with a local resolver.
- `cli.py`: entry point and argument handling.
- `schemas/`: the four vendored schema files, with the version recorded in a README.

## 4. Data model (cobbler)

### 4.1 `triage_assessment`

Append-only. Each row is one assessment of one finding. A finding's current assessment is its most recent row with `approved_at` set.

| Column | Type | Notes |
|---|---|---|
| id | integer PK | |
| finding_id | FK findings.id | not null |
| created_at | timestamptz | not null |
| created_by | string | not null |
| source | enum `human`, `suggested` | `suggested` is reserved for Phase 2 |
| approved_by | string | null until approved |
| approved_at | timestamptz | null until approved |
| is_internet_reachable | boolean | VER-EVA-EIR |
| is_likely_exploitable | boolean | VER-EVA-ELX / AIA |
| current_rating | integer 1–5 | PAIN N-rating |
| potential_agency_impact | text | |
| evaluation_completed_at | timestamptz | starts the VER-TFR-MAV clock |
| projected_reduction_at | timestamptz | |
| projected_reduction_rating | integer 1–5 | |
| reduced_at | timestamptz | when the rating last dropped |
| final_disposition | enum | `fully_mitigated`, `partially_mitigated`, `remediated`, `false_positive`; null while active |
| is_overdue | boolean | |
| overdue_explanation | text | required when `is_overdue` is true |
| supplementary_risk_info | text | |
| is_accepted | boolean | default false |
| acceptance_rationale | text | required when `is_accepted` is true |
| in_kev | boolean | BOD 26-04 "In the KEV" input |
| kev_added_at | timestamptz | null when not in the KEV |
| technical_impact | enum `total_control`, `partial_control` | BOD 26-04 "Technical Impact" input |

The new triage columns sit beside the existing `Finding` status fields. Nothing in the existing status model changes.

### 4.2 `pain_reduction_event`

| Column | Type | Notes |
|---|---|---|
| id | integer PK | |
| finding_id | FK findings.id | |
| reduced_at | timestamptz | |
| rating | integer 1–5 | rating after the reduction |

On approval of an assessment, the endpoint writes a row here if `current_rating` is lower than the previous approved rating.

### 4.3 BOD 26-04 remediation timeline

BOD 26-04 Table 1 gives an agency remediation timeline for each combination of four inputs. The inputs map to the record as follows:

- Publicly exposed = `is_internet_reachable`.
- In the KEV = `in_kev`.
- Automatable by adversary = `is_likely_exploitable`. VER-EVA-AIA already requires assuming automatable unless shown otherwise, so the mapping matches the VER rules.
- Technical impact = `technical_impact` (total control or partial control).

The generator computes the timeline in code. The 16 rows of Table 1 are a versioned constant keyed to the BOD date, so the generator stores no derived timeline. Rows 15 and 16 give "fix on system upgrade" rather than a number of days. Rows 1, 3, and 9 also require a forensic triage, which the run output lists as an action.

**Clock start** = the earlier of `kev_added_at` and `identified_at`, where `identified_at` is `finding.first_found`. This is an assumption (section 11).

Timelines change when the inputs change (BOD 26-04 Appendix A, note 5). Because assessments are append-only, the history of each timeline is kept.

Phase III, which sets these remediation timelines, takes effect on about 2026-12-07. Enforcement depends on applicability (section 11). Phase 1 stores the inputs and computes the timeline regardless.

## 5. Identifiers

`providerTrackingId` is `COB-<finding.id>`. The finding id is stable across scans, because findings are deduplicated by hash. The CodeDx ID and the Jira key are kept as references on the finding and are not used as the tracking ID.

## 6. cobbler API

- `POST /triage/assessments`: creates an unapproved assessment. Body includes `finding_id`, `created_by`, `source`, and the assessment fields.
- `POST /triage/assessments/<id>/approve`: sets `approved_by` and `approved_at`, and writes a `pain_reduction_event` if the rating dropped. Approval requires `is_internet_reachable`, `is_likely_exploitable`, `current_rating`, and `evaluation_completed_at`. It also requires `acceptance_rationale` when `is_accepted` is true and `overdue_explanation` when `is_overdue` is true. Approval returns 422 with the missing fields when any requirement is unmet.
- `GET /findings/<id>/triage`: returns the current approved assessment and the full history.

The report generator reads findings through the existing `GET /findings` endpoint, with `tool_name`, `show_closed=true`, and `show_hidden=true`, and then reads each finding's triage.

## 7. Report rules

### 7.1 Period and activity

A reporting period is `from` and `to`. A finding has activity in the period if any of these hold:

- `first_found` or `last_found` falls in the period.
- `status_date` falls in the period.
- An assessment was approved in the period.
- A `pain_reduction_event` falls in the period.

VER-RPT-PER requires each report to cover all activity since the previous report, so the generator states the period explicitly in each document.

### 7.2 Routing

- Accepted findings (`is_accepted` true in the current assessment) go to AVI.
- All other findings with activity go to VDT.
- MRH includes every active and accepted finding, as a snapshot at `generatedAt`. The provider is Rev5 Class C, so every run produces it. The generator does not schedule itself. The 14-day refresh is an operational requirement (section 10).

### 7.3 Field mapping

- `providerTrackingId` = `COB-<finding.id>`.
- `detection.detectedAt` = `finding.first_found`. `detection.detectionSource` = the tool name (ZAP or CIS).
- `vulnerabilityDescription` = `finding.description`.
- `isInternetReachable`, `isLikelyExploitable`, `currentRating`, `potentialAgencyImpact`, `evaluationCompletedAt`, `projectedNextReduction`, `overdueStatus`, `supplementaryRiskInformation`, `painReductionEvents`, and `finalDisposition` come from the current approved assessment and its events.
- `acceptanceRationale` = `acceptance_rationale`, for AVI.
- Final disposition values map as `fully_mitigated` → "Fully Mitigated", `partially_mitigated` → "Partially Mitigated", `remediated` → "Remediated", `false_positive` → "False Positive".

### 7.4 Gaps

The generator refuses to emit a report that has gaps. It lists every gap and exits non-zero. Gaps are:

- A finding with activity but no approved assessment.
- Missing `isInternetReachable`, `isLikelyExploitable`, `currentRating`, or `evaluationCompletedAt`.
- A missing `vulnerabilityDescription`.
- An active finding more than 192 days past `evaluationCompletedAt` that is neither accepted nor dispositioned (VER-TFR-MAV). Source: https://www.fedramp.gov/2026/providers/20x/rules/vulnerability-evaluation-and-reporting/#mark-accepted-vulnerabilities. The threshold is a constant in the generator, so it can be changed in one place.

### 7.5 Output

The generator validates each document against its schema before writing. It builds each document in memory and writes all of them to the output directory only after every document validates. A failure writes nothing.

## 8. Error handling

- cobbler unreachable or returns an error: the run fails and writes nothing.
- Gaps: listed per finding with the rule that failed, then exit non-zero.
- When the BOD 26-04 check is enforced (section 11): an active finding past its Table 1 timeline from clock start, with no accepted classification or final disposition, or a missing `in_kev` or `technical_impact`.
- Class C warnings (not gaps): a finding whose `evaluationCompletedAt` is more than 5 days after `detection.detectedAt` (VER-TFR-EVU, a should-level requirement for Class C). Warnings are listed in the run output, and the run still writes files.
- Schema validation failure: a bug in the generator. It is reported with the validator message and writes nothing.

## 9. Testing

- **cobbler:** migration tests, and endpoint tests in the existing pytest suite. Tests cover append-only history, current-assessment selection, the approval rule, `pain_reduction_event` creation, and the required-field checks for acceptance and overdue.
- **fedramp-reporting:** unit tests for mapping and routing, with hand-built cobbler responses as fixtures. A validation test for each report type. One gap test per rule in section 7.4. Fixture data is drawn from the 2026-09-17 ZAP analysis, entered by hand.

## 10. Out of scope

- The Trivy importer. Provided separately, then added as a tool in cobbler.
- Phase 2: RAG-suggested assessments. The `source` field is reserved for it.
- Uploading output to GCS or submitting it to FedRAMP.
- The deviation-request workflow.
- Scheduling the 14-day MRH refresh. It is an operational task (for example, a cron job or CI schedule) and is set up after the generator runs reliably.
- Incident treatment under VER-TFR-IRI and VER-TFR-NRI (Class C reportable-incident rules). Triage records can't yet express whether a finding is a reportable incident.
- Backfilling historical triage from the Google Drive Analysis documents.

## 11. Open questions

1. **CIS in VER.** CIS benchmark conformance issues are configuration findings, not necessarily vulnerabilities. The spec includes them as findings with tool CIS until this is answered.
2. **Backfill.** Backfill is required, one way or another. The source may be the POA&M, which is not yet decided. The first report period will have gaps until backfill is loaded into cobbler, and the generator reports those gaps rather than hiding them. Backfill is out of scope for Phase 1 code, but the plan must include a loader step, and the source format is needed before that step is designed.
3. **Provider class.** Resolved: Rev5 Class C. The spec's MRH and Class C requirements in sections 1, 7.2, and 10 follow from this.
4. **Certification package overview URI.** The schema defines this as the full URI of the provider's Certification Package Overview document. The Rev5 Class C CPO rules (CPO-CSO-OVR, CPO-CSO-MTD) require the overview to be included in the certification package in human-readable and JSON form. They don't define a URL. The CLI takes the URI as an input, and its value must come from you.
5. **BOD 26-04 applicability.** Does the directive reach us through our procurement contract, or only through the FedRAMP PMO? This decides whether the section 7.4 BOD check is enforced. Phase 1 stores the inputs and computes the timelines either way.
6. **Clock start.** The spec assumes `identified_at` is `finding.first_found`. Confirm that, or name the source of the identification date.
7. **Input sources.** The CISA vulnhancement data in the stored Trivy JSON may carry SSVC automatable and technical-impact values and KEV status. I haven't checked a sample. If it does, those inputs can be filled automatically instead of entered by hand. Phase 1 covers ZAP and CIS, which don't have this data.

## 12. Implementation split

This spec covers two repos, so the implementation plan should split it into two tracks: cobbler (migrations, endpoints, tests) and fedramp-reporting (client, mapping, validation, CLI, tests). The cobbler track comes first, because the generator reads from it.
