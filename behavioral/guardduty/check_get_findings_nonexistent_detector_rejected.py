"""get-findings-nonexistent-detector-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-findings-nonexistent-detector-rejected"
GROUP = "overly-permissive"
SERVICES = ["guardduty"]


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data", "resource:account-singleton:guardduty-detector")
def run(ctx) -> None:
    """GetFindings against a detectorId that was never created is rejected with
    BadRequestException, rather than returning an empty success payload."""
    gd = ctx.client("guardduty")

    bogus_detector_id = "f" * 32
    err = _error(
        lambda: gd.get_findings(
            DetectorId=bogus_detector_id,
            FindingIds=["0" * 32],
        )
    )
    assert err["Code"] == "BadRequestException", f"expected BadRequestException, got {err!r}"
    expected = "The request is rejected because the input detectorId is not owned by the current account."
    assert err["Message"] == expected, f"expected message {expected!r}, got {err['Message']!r}"

    # Positive control: GetFindings against a real detector/finding succeeds normally,
    # proving the rejection above is specific to the nonexistent detector, not a
    # blanket failure of the operation.
    detector_id, owned = _get_or_create_detector(gd)
    if owned:
        ctx.on_cleanup(lambda: gd.delete_detector(DetectorId=detector_id))
    gd.create_sample_findings(DetectorId=detector_id)
    finding_ids = _poll_until(
        lambda: gd.list_findings(DetectorId=detector_id).get("FindingIds", []),
        lambda ids: len(ids) > 0,
        timeout_s=90,
        interval_s=3,
    )
    # GetFindings lags ListFindings' own index: an id ListFindings just returned can
    # still answer 0 findings (no UnprocessedFindings entry either) for a few seconds
    # after it first becomes listable. Bound the wait rather than asserting on the
    # first read.
    resp = _poll_until(
        lambda: gd.get_findings(DetectorId=detector_id, FindingIds=finding_ids[:1]),
        lambda r: len(r.get("Findings", [])) == 1,
        timeout_s=60,
        interval_s=3,
    )
    assert len(resp["Findings"]) == 1, (
        f"expected 1 finding for id {finding_ids[0]!r}, got "
        f"{len(resp['Findings'])} (unprocessed={resp.get('UnprocessedFindings')!r})"
    )
    assert resp["Findings"][0]["Id"] == finding_ids[0], (
        f"expected finding id {finding_ids[0]!r}, got {resp['Findings'][0]['Id']!r}"
    )


def _error(fn):
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _get_or_create_detector(gd):
    """GuardDuty allows only one detector per account per Region. Adopt an existing
    one rather than racing a concurrent creator; never mutate or delete an adopted
    detector beyond what this check itself needs (read-only use as a positive control)."""
    existing = gd.list_detectors().get("DetectorIds", [])
    if existing:
        return existing[0], False
    tags = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"}
    try:
        detector_id = gd.create_detector(Enable=True, Tags=tags)["DetectorId"]
        return detector_id, True
    except ClientError:
        existing = gd.list_detectors().get("DetectorIds", [])
        if existing:
            return existing[0], False
        raise


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


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
