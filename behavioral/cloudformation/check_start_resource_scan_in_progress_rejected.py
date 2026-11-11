"""start-resource-scan-in-progress-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "start-resource-scan-in-progress-rejected"
GROUP = "overly-permissive"
SERVICES = ["cloudformation"]

_SCAN_FILTERS = [{"Types": ["AWS::SNS::Topic"]}]


@tags(
    "axis:rejection", "cap:c1", "concern:negative-classes", "plane:control",
    "resource:account-singleton:cfn-resource-scan",
)
def run(ctx) -> None:
    """StartResourceScan while the check's own scan is IN_PROGRESS fails with ResourceScanInProgress and the
    exact "active ResourceScan in progress" message and starts no second scan, and the first scan
    is still IN_PROGRESS afterwards."""
    cfn = ctx.client("cloudformation")

    # A one-type scan holds the account's single scan slot for tens of seconds, far longer than the
    # probes below; the check waits for it to finish so the slot is free when it ends.
    first_id = _start_own_scan(ctx, cfn, ScanFilters=_SCAN_FILTERS)
    ctx.on_cleanup(lambda: _wait_scan_settled(None, cfn, first_id, cap_s=50.0))

    before = cfn.describe_resource_scan(ResourceScanId=first_id)["Status"]
    assert before == "IN_PROGRESS", (
        f"the scan {first_id} this check started must be IN_PROGRESS before the second call, got {before!r}"
    )

    second_id, second_err = _start(cfn)
    assert second_id is None, (
        f"expected the second StartResourceScan call to be rejected while {first_id} was still "
        f"running, but it started an independent second scan {second_id}"
    )
    code, msg = second_err
    # CloudFormation carries this awsQuery code without the modeled "Exception" suffix.
    assert code == "ResourceScanInProgress", (
        f"expected ResourceScanInProgress for the second concurrent scan, got {code!r} ({msg!r})"
    )
    expected_msg = (
        "There is an active ResourceScan in progress. Please wait for it to finish before "
        "starting a new ResourceScan. Describe ResourceScans to see the status of the "
        "in-progress ResourceScan."
    )
    assert msg == expected_msg, f"expected message {expected_msg!r}, got {msg!r}"

    described = cfn.describe_resource_scan(ResourceScanId=first_id)
    assert described["ResourceScanId"] == first_id, (
        f"DescribeResourceScan({first_id}) returned a different scan id: {described.get('ResourceScanId')!r}"
    )
    assert described["Status"] == "IN_PROGRESS", (
        f"the held scan {first_id} must still be IN_PROGRESS after the rejection, got {described['Status']!r}"
    )

    _wait_scan_settled(ctx, cfn, first_id)


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _start_own_scan(ctx, cfn, cap_s=600.0, **kwargs):
    """StartResourceScan for this check. The account holds one running scan per region, so while
    another caller's scan holds the slot the call is repeated (capped) until it starts this one.
    A refusal while ListResourceScans shows no scan in progress, twice in a row, fails."""
    timeout_s = _budget_s(ctx, cap_s)
    deadline = time.monotonic() + timeout_s
    unexplained = 0
    while True:
        try:
            return cfn.start_resource_scan(**kwargs)["ResourceScanId"]
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code not in ("ResourceScanInProgress", "ResourceScanInProgressException", "ThrottlingException"):
                raise
        if code != "ThrottlingException":
            running = any(
                s.get("Status") == "IN_PROGRESS"
                for page in cfn.get_paginator("list_resource_scans").paginate()
                for s in page.get("ResourceScanSummaries", [])
            )
            unexplained = 0 if running else unexplained + 1
            assert unexplained < 2, (
                f"StartResourceScan answered {code} while ListResourceScans listed no scan IN_PROGRESS"
            )
        if time.monotonic() >= deadline:
            if _budget_spent(ctx):
                raise TimeoutError("StartResourceScan waiting for the account's running scan to "
                                   "finish: the run budget ended first; not graded")
            raise AssertionError(f"another resource scan held the account's scan slot for {timeout_s}s")
        time.sleep(5)


def _wait_scan_settled(ctx, cfn, scan_id, cap_s=240.0):
    """Poll DescribeResourceScan until scan_id leaves IN_PROGRESS, so the account's scan slot is
    free again before the check ends. Capped by cap_s and, given a ctx, by the run budget (a
    teardown passes none: the runner bounds it); a scan still running raises."""
    timeout_s = cap_s if ctx is None else _budget_s(ctx, cap_s)
    deadline = time.monotonic() + timeout_s
    while cfn.describe_resource_scan(ResourceScanId=scan_id)["Status"] == "IN_PROGRESS":
        if time.monotonic() >= deadline:
            if ctx is not None and _budget_spent(ctx):
                raise TimeoutError(f"resource scan {scan_id} still IN_PROGRESS when the run budget "
                                   "ended; not graded")
            raise AssertionError(f"resource scan {scan_id} still IN_PROGRESS after {timeout_s}s")
        time.sleep(3)


def _start(cfn):
    """(scan id, None) on success, else (None, (code, message)).

    A bare ThrottlingException is API-level request throttling, distinct from the
    business rejection under test; it is retried a short, bounded number of times.
    """
    deadline = time.monotonic() + 15
    while True:
        try:
            return cfn.start_resource_scan(ScanFilters=_SCAN_FILTERS)["ResourceScanId"], None
        except ClientError as e:
            err = e.response["Error"]
            if err["Code"] == "ThrottlingException" and time.monotonic() < deadline:
                time.sleep(2)
                continue
            return None, (err["Code"], err.get("Message"))


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

