"""create-sample-findings-server-generated-fields."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "create-sample-findings-server-generated-fields"
GROUP = "server-side"
SERVICES = ["guardduty"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation", "dp:api", "plane:data", "resource:account-singleton:guardduty-detector")
def run(ctx) -> None:
    """CreateSampleFindings produces findings server-side: severity/type/resource/
    title/description are all populated by GuardDuty and are retrievable via
    GetFindings, even though the caller supplied no finding content at all."""
    gd = ctx.client("guardduty")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    detector_id = _get_or_create_detector(ctx, gd)

    # No FindingTypes given -> GuardDuty decides which sample findings to create.
    gd.create_sample_findings(DetectorId=detector_id)

    finding_ids = _poll_until(
        lambda: gd.list_findings(DetectorId=detector_id).get("FindingIds", []),
        lambda ids: len(ids) > 0,
        timeout_s=90,
        interval_s=3,
    )
    assert len(finding_ids) > 0, "ListFindings returned no sample finding ids"

    sample_ids = finding_ids[: min(5, len(finding_ids))]
    # GetFindings is a separate read path from ListFindings and lags it briefly for
    # freshly created sample findings, so a one-shot call flakes; poll until it
    # catches up to the ids ListFindings already reported.
    findings = _poll_until(
        lambda: gd.get_findings(DetectorId=detector_id, FindingIds=sample_ids)["Findings"],
        lambda fs: len(fs) == len(sample_ids),
        timeout_s=60,
        interval_s=3,
    )
    assert len(findings) == len(sample_ids), (
        f"GetFindings returned {len(findings)} findings for {len(sample_ids)} "
        f"requested ids {sample_ids}; got ids "
        f"{[f.get('Id') for f in findings]}"
    )

    for finding in findings:
        # We never supplied a Type, Severity, Resource, Title, or AccountId -- these
        # are all populated server-side from GuardDuty's built-in sample catalog.
        assert finding["Id"] in sample_ids, f"finding id {finding['Id']!r} not among requested {sample_ids}"
        assert finding["AccountId"] == account_id, (
            f"finding {finding['Id']} AccountId={finding['AccountId']!r} != caller account {account_id!r}"
        )
        assert isinstance(finding["Type"], str) and ":" in finding["Type"], (
            f"finding {finding['Id']} Type={finding.get('Type')!r} is not a colon-namespaced GuardDuty type"
        )
        assert isinstance(finding["Severity"], float) and finding["Severity"] > 0, (
            f"finding {finding['Id']} Severity={finding.get('Severity')!r} is not a positive float"
        )
        assert isinstance(finding["Resource"], dict) and len(finding["Resource"]) > 0, (
            f"finding {finding['Id']} Resource={finding.get('Resource')!r} is not a populated dict"
        )
        assert finding.get("Title"), f"finding {finding['Id']} has no Title"
        assert finding["Region"] == ctx.region, (
            f"finding {finding['Id']} Region={finding.get('Region')!r} != {ctx.region!r}"
        )


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    result = probe()
    while time.monotonic() < deadline:
        if predicate(result):
            return result
        time.sleep(interval_s)
        result = probe()
    if predicate(result):
        return result
    raise AssertionError(f"condition not met within {timeout_s}s (last={result!r})")


def _get_or_create_detector(ctx, gd):
    # GuardDuty allows exactly one detector per account per region; adopt one if
    # present instead of assuming a fresh account, and only clean up what we create.
    ids = gd.list_detectors().get("DetectorIds", [])
    if ids:
        return ids[0]
    detector_id = gd.create_detector(Enable=True)["DetectorId"]
    ctx.on_cleanup(lambda: gd.delete_detector(DetectorId=detector_id))
    return detector_id


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
