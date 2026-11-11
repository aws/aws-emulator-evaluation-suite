"""generated-template-and-scan-not-found-errors."""
from __future__ import annotations

import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "generated-template-and-scan-not-found-errors"
GROUP = 'resources'
SERVICES = ['cloudformation']


def _client_error(fn):
    """Call fn(); return botocore (Code, Message) of the ClientError it raises. An unexpected
    SUCCESS raises AssertionError."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")

def _expect_code(fn, base, message):
    """Assert fn() raises a ClientError whose code is `base` (bare or with the 'Exception'
    suffix of the shape name) and, unless `message` is None, whose message is exactly
    `message`. Returns the message."""
    code, actual = _client_error(fn)
    allowed = {base, base + "Exception"} if not base.endswith("Exception") else {base}
    assert code in allowed, f"expected one of {sorted(allowed)}, got {code!r} ({actual!r})"
    if message is not None:
        assert actual == message, f"{code}: expected message {message!r}, got {actual!r}"
    return actual


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


@tags(
    "axis:rejection", "cap:c1", "concern:negative-classes", "plane:control",
    "resource:account-singleton:cfn-resource-scan",
)
def run(ctx) -> None:
    """Unknown generated-template/resource-scan ids raise their respective
    NotFoundExceptions; listing scan results while the scan is still
    IN_PROGRESS raises ResourceScanInProgressException."""
    cf = ctx.client("cloudformation")
    account = ctx.client("sts").get_caller_identity()["Account"]

    missing_gt = ctx.unique_name("sim2real-behav-gt-missing-")
    # The generated-template refusals end in a per-call request id
    # ("... (Service: ...; Request ID: <uuid>; Proxy: null)"): grade the stable prefix and suffix.
    gt_prefix = f"Template with arn {missing_gt} does not exist (Service: "
    for call in (
        lambda: cf.describe_generated_template(GeneratedTemplateName=missing_gt),
        lambda: cf.get_generated_template(GeneratedTemplateName=missing_gt),
        lambda: cf.delete_generated_template(GeneratedTemplateName=missing_gt),
    ):
        message = _expect_code(call, "GeneratedTemplateNotFound", None)
        assert message.startswith(gt_prefix) and message.endswith("; Proxy: null)"), (
            f"GeneratedTemplateNotFound message: {message!r}"
        )

    missing_scan = (
        f"arn:aws:cloudformation:{ctx.region}:{account}:resourceScan/{uuid.uuid4()}"
    )
    for call in (
        lambda: cf.describe_resource_scan(ResourceScanId=missing_scan),
        lambda: cf.list_resource_scan_resources(ResourceScanId=missing_scan),
        lambda: cf.list_resource_scan_related_resources(
            ResourceScanId=missing_scan,
            Resources=[
                {
                    "ResourceType": "AWS::SNS::Topic",
                    "ResourceIdentifier": {"TopicArn": "arn:aws:sns:us-west-2:123456789012:missing"},
                }
            ],
        ),
    ):
        message = _expect_code(call, "ResourceScanNotFound", None)
        assert message == "There is no ResourceScan found for the ResourceScanId.", (
            f"ResourceScanNotFound message: {message!r}"
        )

    # CloudFormation allows one resource scan per account/region at a time.
    # The check starts its own one-type scan and probes it at once: the scan
    # stays IN_PROGRESS for tens of seconds, so the window is held by the scan
    # itself, and the check waits for it to finish so the slot is free when it ends.
    scan_id = _start_own_scan(ctx, cf, ScanFilters=[{"Types": ["AWS::SNS::Topic"]}])
    ctx.on_cleanup(lambda: _wait_scan_settled(None, cf, scan_id, cap_s=50.0))

    status = cf.describe_resource_scan(ResourceScanId=scan_id).get("Status")
    assert status == "IN_PROGRESS", f"a just-started resource scan must be IN_PROGRESS, got {status!r}"
    _expect_code(
        lambda: cf.list_resource_scan_resources(ResourceScanId=scan_id),
        "ResourceScanInProgress",
        (
            "The ResourceScan is in progress. Please wait for it to finish before performing any "
            "further operations on it. Describe ResourceScans to see the status of the in-progress "
            "ResourceScan."
        ),
    )
    _wait_scan_settled(ctx, cf, scan_id)

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
