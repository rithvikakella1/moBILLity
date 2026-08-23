"""Coding accuracy benchmark.

This is the only thing standing behind the precision figure on the landing page.
Re-run it whenever the prompt, the model, or the confidence threshold changes,
and update the landing page if the number moves -- a published accuracy claim
that no longer matches the measurement is worse than no claim at all.

The expected codes here are NOT coder-verified, so the landing page says
"internal benchmark" and names the sample size. Both the number and that
qualifier change together once a certified coder has reviewed the case file.

Deliberately NOT part of the pytest suite: it makes real API calls and costs
money. Run it by hand before any prompt or model change.

    python tests/benchmark.py                  # both modes at threshold 0.75
    python tests/benchmark.py --sweep          # metrics vs. confidence threshold
    python tests/benchmark.py --cases my.json

TWO SCORING MODES, reported side by side, because they answer different
questions and the gap between them is itself the interesting number:

  confirmed            Only confirmed_codes count as predictions. This is what
                       the tool would put on a claim, so it is the number that
                       matters for billing risk.

  confirmed+suggested  Confirmed and suggested codes both count. Suggested
                       codes are surfaced to a human for review, so a code
                       found here was not missed -- it was flagged. This is the
                       honest measure of "did the extractor see it at all", and
                       the ceiling on what a coder using the tool could catch.

Precision moves the other way between the two: every suggested code that is not
in the expected set becomes a false positive. That trade is the point. A large
recall gain for a small precision loss says the suggestion channel is earning
its place; the reverse says it is mostly noise.

The case file is a JSON list, or an object with a "cases" list plus whatever
metadata you want to keep alongside it. Notes must be de-identified, and the
expected codes should be verified by a working coder -- that review is what
makes the resulting number credible:

    [
      {
        "id": "case-001",
        "note": "De-identified clinical note text...",
        "expected": {
          "ICD-10-CM": ["E11.9", "I10"],
          "CPT": ["99213"],
          "HCPCS": ["J0696"]
        }
      }
    ]
"""
import argparse
import json
import os
import sys
from collections import defaultdict

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

DEFAULT_CASES = os.path.join(os.path.dirname(os.path.abspath(__file__)), "benchmark_cases.json")
DEFAULT_OUTPUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "benchmark_results.json")

CONFIRMED = "confirmed"
WITH_SUGGESTED = "confirmed+suggested"
MODES = (CONFIRMED, WITH_SUGGESTED)


def normalize(code: str) -> str:
    return str(code).strip().upper().replace(" ", "")


def score(predicted: set, expected: set) -> dict:
    """Precision, recall, and F1 for one code set.

    Exact match only: a truncated ICD-10 code is wrong, as the system prompt
    itself states, so partial credit would measure the wrong thing.
    """
    true_positives = len(predicted & expected)
    precision = true_positives / len(predicted) if predicted else (1.0 if not expected else 0.0)
    recall = true_positives / len(expected) if expected else 1.0
    f1 = (
        2 * precision * recall / (precision + recall)
        if (precision + recall)
        else 0.0
    )
    return {
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
        "true_positives": true_positives,
        "predicted_count": len(predicted),
        "expected_count": len(expected),
        "false_positives": sorted(predicted - expected),
        "false_negatives": sorted(expected - predicted),
    }


def collect(result: dict, threshold: float) -> tuple[dict, dict]:
    """Group predicted codes by code system, split by channel.

    The threshold applies only to confirmed codes -- suggested codes carry no
    confidence field, by design: the model routes a code there precisely when
    it cannot support a number.
    """
    confirmed = defaultdict(set)
    for item in result.get("confirmed_codes", []):
        try:
            confidence = float(item.get("confidence", 0))
        except (TypeError, ValueError):
            continue
        if confidence < threshold:
            continue
        confirmed[normalize(item.get("code_type", "UNKNOWN"))].add(normalize(item.get("code", "")))

    suggested = defaultdict(set)
    for item in result.get("suggested_codes", []):
        suggested[normalize(item.get("code_type", "UNKNOWN"))].add(normalize(item.get("code", "")))

    return confirmed, suggested


def _predicted_for(mode: str, confirmed: dict, suggested: dict) -> dict:
    if mode == CONFIRMED:
        return {system: set(codes) for system, codes in confirmed.items()}
    merged = defaultdict(set)
    for source in (confirmed, suggested):
        for system, codes in source.items():
            merged[system] |= codes
    return merged


def provenance(expected: dict, confirmed: dict, suggested: dict) -> dict:
    """Where each expected code was found: confirmed, suggested only, or missed.

    This is the breakdown the two headline modes cannot show on their own -- it
    says how much of the recall in confirmed+suggested mode is carried by the
    suggestion channel rather than by codes the model was already sure of.
    """
    in_confirmed, in_suggested, missed = [], [], []
    for system, codes in expected.items():
        for code in codes:
            label = f"{system} {code}"
            if code in confirmed.get(system, set()):
                in_confirmed.append(label)
            elif code in suggested.get(system, set()):
                in_suggested.append(label)
            else:
                missed.append(label)
    return {
        "confirmed": sorted(in_confirmed),
        "suggested_only": sorted(in_suggested),
        "missed": sorted(missed),
    }


def run(cases: list, thresholds: list) -> dict:
    import app as application

    raw_results = []
    for index, case in enumerate(cases, 1):
        print(f"  [{index}/{len(cases)}] {case.get('id', index)}", flush=True)
        try:
            extracted = application.extract_medical_codes(case["note"])
        except Exception as error:  # noqa: BLE001 - one bad case must not end the run
            print(f"      extraction failed: {error}")
            extracted = {"confirmed_codes": [], "suggested_codes": []}
        raw_results.append({"case": case, "extracted": extracted})

    report = {"case_count": len(cases), "modes": {mode: {} for mode in MODES}}

    for threshold in thresholds:
        # Provenance depends on the threshold (a code below it drops out of the
        # confirmed channel) but not on the mode, so compute it once per pass.
        totals_provenance = {"confirmed": 0, "suggested_only": 0, "missed": 0}
        per_mode_totals = {mode: defaultdict(lambda: {"predicted": set(), "expected": set()})
                           for mode in MODES}
        per_mode_cases = {mode: [] for mode in MODES}
        exact_matches = dict.fromkeys(MODES, 0)

        for entry in raw_results:
            case, extracted = entry["case"], entry["extracted"]
            confirmed, suggested = collect(extracted, threshold)
            expected = {
                normalize(system): {normalize(code) for code in codes}
                for system, codes in case.get("expected", {}).items()
            }

            where = provenance(expected, confirmed, suggested)
            for bucket in totals_provenance:
                totals_provenance[bucket] += len(where[bucket])

            for mode in MODES:
                predicted = _predicted_for(mode, confirmed, suggested)
                case_scores = {}
                flat_predicted, flat_expected = set(), set()
                for system in set(predicted) | set(expected):
                    got, want = predicted.get(system, set()), expected.get(system, set())
                    case_scores[system] = score(got, want)
                    tagged_got = {(case["id"], system, c) for c in got}
                    tagged_want = {(case["id"], system, c) for c in want}
                    per_mode_totals[mode][system]["predicted"] |= tagged_got
                    per_mode_totals[mode][system]["expected"] |= tagged_want
                    flat_predicted |= tagged_got
                    flat_expected |= tagged_want

                # A code emitted under the wrong system label (G0439 tagged CPT
                # when it is HCPCS) scores as both a false positive and a false
                # negative, which reads as two coding errors when it is one
                # labelling error. Count them so the distinction is visible.
                mislabelled = 0
                for system in set(predicted) | set(expected):
                    for code in predicted.get(system, set()) - expected.get(system, set()):
                        if any(code in expected.get(other, set())
                               for other in expected if other != system):
                            mislabelled += 1

                is_exact = flat_predicted == flat_expected
                exact_matches[mode] += int(is_exact)
                per_mode_cases[mode].append({
                    "id": case.get("id"),
                    "exact_match": is_exact,
                    "mislabelled_system": mislabelled,
                    "systems": case_scores,
                    "found_in": where,
                })

        for mode in MODES:
            totals = per_mode_totals[mode]
            all_predicted = set().union(*(v["predicted"] for v in totals.values())) if totals else set()
            all_expected = set().union(*(v["expected"] for v in totals.values())) if totals else set()
            report["modes"][mode][str(threshold)] = {
                "overall": score(all_predicted, all_expected),
                # Share of cases where the predicted set matched the expected set
                # exactly -- no extra codes, none missing. Harsh, and the metric
                # closest to "a coder could accept this without editing".
                "exact_match_rate": round(exact_matches[mode] / len(cases), 4) if cases else 0.0,
                "by_system": {
                    system: score(values["predicted"], values["expected"])
                    for system, values in totals.items()
                },
                "per_case": per_mode_cases[mode],
                "provenance": totals_provenance,
            }

    return report


def _print_summary(report: dict) -> None:
    """Precision first.

    For a billing tool the two error types are not symmetric. A false confirmed
    code becomes a denied claim or an overpayment to unwind; a missed code costs
    a coder one catch they were already going to look for. So the headline is
    precision and the concrete burden it implies -- false positives per note --
    with recall reported as the constraint that stops precision being gamed by
    coding nothing.
    """
    cases = report["case_count"]
    thresholds = list(report["modes"][CONFIRMED].keys())

    print("PRECISION (confirmed mode) -- the billing-risk number")
    print(f"{'thresh':>8}{'precision':>11}{'FP':>6}{'FP/note':>9}{'recall':>9}")
    print("-" * 43)
    for threshold in thresholds:
        overall = report["modes"][CONFIRMED][threshold]["overall"]
        false_pos = overall["predicted_count"] - overall["true_positives"]
        print(f"{threshold:>8}{overall['precision']:>11.3f}{false_pos:>6}"
              f"{false_pos / cases:>9.2f}{overall['recall']:>9.3f}")

    best = max(thresholds, key=lambda t: report["modes"][CONFIRMED][t]["overall"]["precision"])
    spread = (report["modes"][CONFIRMED][best]["overall"]["precision"]
              - min(report["modes"][CONFIRMED][t]["overall"]["precision"] for t in thresholds))
    if spread < 0.005:
        print("\nThe threshold is inert: precision is identical across the whole")
        print("sweep, so the model's self-reported confidence carries no signal")
        print("here. Precision has to come from the prompt or from validation,")
        print("not from where this cut is placed.")
    else:
        print(f"\nHighest precision at threshold {best}.")
    print()

    header = (
        f"{'mode':<22}{'thresh':>7}{'precis':>9}{'recall':>8}"
        f"{'f1':>7}{'exact':>7}{'TP':>5}{'FP':>5}{'FN':>5}"
    )
    print(header)
    print("-" * len(header))
    for threshold in thresholds:
        for mode in MODES:
            block = report["modes"][mode][threshold]
            overall = block["overall"]
            false_pos = overall["predicted_count"] - overall["true_positives"]
            false_neg = overall["expected_count"] - overall["true_positives"]
            print(
                f"{mode:<22}{threshold:>7}{overall['precision']:>9.3f}"
                f"{overall['recall']:>8.3f}{overall['f1']:>7.3f}"
                f"{block['exact_match_rate']:>7.3f}"
                f"{overall['true_positives']:>5}{false_pos:>5}{false_neg:>5}"
            )
        print()

    # The provenance split is identical across modes; read it off either one.
    last = report["modes"][CONFIRMED][thresholds[-1]]
    mislabelled = sum(c.get("mislabelled_system", 0) for c in last["per_case"])
    if mislabelled:
        print(f"{mislabelled} of the false positives are the right code under the wrong")
        print("system label -- one labelling error each, scored as two coding errors.\n")
    where = last["provenance"]
    total = sum(where.values())
    if total:
        print(f"Of {total} expected codes at threshold {thresholds[-1]}:")
        print(f"  {where['confirmed']:>4} found as confirmed")
        print(f"  {where['suggested_only']:>4} found only as suggested")
        print(f"  {where['missed']:>4} missed entirely")
        strict = report["modes"][CONFIRMED][thresholds[-1]]["overall"]["recall"]
        lenient = report["modes"][WITH_SUGGESTED][thresholds[-1]]["overall"]["recall"]
        print(f"\nSuggestions lift recall {strict:.3f} -> {lenient:.3f} "
              f"(+{lenient - strict:.3f}).")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cases", default=DEFAULT_CASES)
    parser.add_argument("--output", default=DEFAULT_OUTPUT)
    parser.add_argument(
        "--threshold", type=float, default=0.75,
        help="confidence cut for the confirmed channel (default: 0.75, matching app.py)",
    )
    parser.add_argument(
        "--sweep", action="store_true",
        help="score across thresholds 0.50-0.95 to pick the operating point",
    )
    args = parser.parse_args()

    if not os.path.exists(args.cases):
        print(f"No case file at {args.cases}.\n")
        print("Build one from de-identified notes with coder-verified codes.")
        print("See the module docstring for the expected shape. Suggested sources:")
        print("  - MIMIC-IV discharge summaries (requires PhysioNet credentialing)")
        print("  - CMS documentation and coding examples")
        print("  - AAPC practice cases")
        print("\n50-100 cases is enough for a defensible number.")
        return 1

    with open(args.cases, encoding="utf-8") as handle:
        loaded = json.load(handle)
    # Accept a bare list, or an object carrying metadata beside the cases.
    cases = loaded["cases"] if isinstance(loaded, dict) else loaded
    for index, case in enumerate(cases):
        case.setdefault("id", f"case-{index + 1:03d}")

    thresholds = (
        [round(0.50 + 0.05 * step, 2) for step in range(10)]
        if args.sweep
        else [args.threshold]
    )
    print(f"Running {len(cases)} case(s) against the live model...")
    report = run(cases, thresholds)

    with open(args.output, "w", encoding="utf-8") as handle:
        json.dump(report, handle, indent=2)

    print(f"\nWrote {args.output}\n")
    _print_summary(report)
    print(
        "\nFor billing, weight precision over recall in confirmed mode: a false "
        "confirmed code costs more\nthan a missed suggestion. Publish the number "
        "you measure, with the case count and mode beside it."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
