# Patient care portal

The patient experience lives at `/patient.html` (static hosting) or `/patient`
(FastAPI). The clinician Workflow Hub links to the preview. All sample records
are fictional and held in client memory. Reloading discards changes. There are no
patient-data API calls, message sends, real scheduling actions, payments, or
caregiver permission changes in this implementation.

## Implemented experience

- **Overview:** next appointment, actionable care checklist, prescription pickup,
  new results, clinician note, and quick actions.
- **Care plan:** doctor instructions and read acknowledgment, follow-up checklist,
  referral milestones, care team, preparation goal, preventive-care questions,
  personal symptom/reading/question journal.
- **Visits:** upcoming and historical encounters, summaries, pre-visit checklist,
  saved questions, clearly labeled sample calendar downloads, rescheduling and
  accommodation request drafts.
- **Results:** laboratory and imaging categories, original sample values, units,
  reference intervals, flags, numerically accurate trends, clinician notes,
  report downloads, missing-result and interpretation-question drafts.
- **Medications:** sample name/strength/purpose/instructions/prescriber/supply,
  daily demo checkoffs, pickup location and hours, allergies, refill and medication
  reconciliation drafts, cost/access questions.
- **Messages:** sample care-team threads, unread indicators, local draft create,
  edit and delete. Request forms create explicitly unsent drafts.
- **Telehealth:** pre-visit room, optional device-permission-based local camera and
  microphone test, clear disconnected state. Tracks stop on close, Escape, route
  changes, navigation away, and stop button. Audio/video is not recorded or sent.
- **Records and support:** encounter summaries, timeline, medication/allergy list,
  outside-record requests, immunization-data completeness, billing/coverage and
  financial-assistance questions, transportation/interpreter/accessibility
  requests, caregiver scope planning, reminder preferences, large text and
  contrast controls.

## Integration boundary

Do not replace fictional records with live data in this static page without the
following server-side foundations. Existing clinician authentication and
`owner_user_id` appointment ownership do **not** authorize a patient account to
read a clinician's patients.

1. **Identity and enrollment:** distinct patient role, verified enrollment linking
   an account to a patient record, account recovery, MFA/session management,
   patient/clinician role separation, reauthentication for sensitive changes.
2. **Authorization:** enforce patient-scoped access on every resource and download;
   test cross-patient and cross-practice access. Avoid identifying a patient from
   an arbitrary query parameter, email address, or client-side selector.
3. **Clinical record contracts:** source identifiers, clinician/practice ownership,
   timestamps, timezone, provenance, release/review status, amendments, pagination,
   stale-data handling, and audit events. Treat lab reference intervals, units,
   critical flags, and instructions as source data; do not infer recommendations.
4. **Scheduling:** server time, verified slots, booking concurrency, cancellations,
   waitlists, visit types, accommodations, preparation instructions, source-system
   reconciliation, explicit confirmation of accepted changes.
5. **Results and documents:** EHR/lab adapters, patient matching, lawful release,
   original reports, accessible downloads, source-specific ranges, result amendment
   and review workflows. Secure attachment scanning and controlled access.
6. **Medication and pharmacy:** authoritative prescription list, reconciliation,
   refill-review queue, real pharmacy fulfillment and hours, clinical sign-off,
   discontinuation/dose-change history, allergy provenance. Self-reported adherence
   must stay distinct from clinician-verified administration.
7. **Messaging:** authenticated care-team inbox, routing, availability/response
   expectations, attachment handling, delivery receipts, appropriate urgent-care
   instructions, and audit/retention. Never simulate a sent or reviewed state.
8. **Telehealth:** approved vendor/session provisioning tied to an appointment,
   short-lived access, waiting-room controls, consent, device permissions,
   accessibility/interpreter support, disconnection/rejoin handling, fallback
   contact, and no recording unless separately consented and configured.
9. **Reminders:** verified channel and consent, quiet hours/timezone, opt-out,
   content minimization, delivery status, retry policy, and source change handling.
   Preference controls here do not change existing clinician reminder consent.
10. **Caregiver/proxy access:** verified invite, independently authenticated helper,
    granular and time-limited/revocable grants, patient visibility and audit,
    appropriate minor/guardian and sensitive-record policies.
11. **Billing:** verified payer/provider data, itemized statements, estimates versus
    actual balances, financial assistance workflow. No inferred coverage or payment
    commitments. Use a compliant payment provider if payments are later added.
12. **Operations:** encrypted storage/transit, retention/deletion, incident response,
    audit and export, accessibility testing, privacy requirements and organizational
    agreements, clinical safety review, consent/version history, monitoring and
    support. Health journal entries must not imply clinical monitoring.

## Review

Serve the repository locally and open `/patient.html`. All forms accept fictional
preview data only. Downloads explicitly identify themselves as fictional. Test
navigation and dialogs with keyboard, mobile layout, patient journey continuity,
positive and negative form validation, camera-denial/unavailable states, device
track cleanup, draft editing, and print/download usability.
