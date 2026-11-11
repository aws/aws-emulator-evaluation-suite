"""resource-scan-not-found-rejected."""
from __future__ import annotations

import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "resource-scan-not-found-rejected"
GROUP = "error-semantics"
SERVICES = ["cloudformation"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control", "resource:account-singleton:cfn-resource-scan")
def run(ctx) -> None:
    """DescribeResourceScan and the two ListResourceScan* APIs reject a never-created scan id with
    ResourceScanNotFound, after the same APIs succeed against a real COMPLETE scan."""
    cfn = ctx.client("cloudformation")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    # Positive control: adopt-or-create a real resource scan (only one may run
    # per account/Region at a time) and drive it to COMPLETE, then confirm the
    # same three read APIs this check probes all succeed against it.
    try:
        scan_id = cfn.start_resource_scan(ScanFilters=[{"Types": ["AWS::SNS::Topic"]}])["ResourceScanId"]
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        if code not in ("ResourceScanInProgressException", "ResourceScanInProgress"):
            raise
        in_progress = [
            s for s in cfn.list_resource_scans().get("ResourceScanSummaries", [])
            if s["Status"] == "IN_PROGRESS"
        ]
        assert in_progress, f"{code} but no IN_PROGRESS scan is listed"
        scan_id = in_progress[0]["ResourceScanId"]

    deadline = time.monotonic() + 900
    status = cfn.describe_resource_scan(ResourceScanId=scan_id)["Status"]
    while status not in ("COMPLETE", "FAILED", "EXPIRED") and time.monotonic() < deadline:
        time.sleep(2)
        status = cfn.describe_resource_scan(ResourceScanId=scan_id)["Status"]
    assert status == "COMPLETE", f"resource scan {scan_id} did not reach COMPLETE within budget (status={status})"

    live_resources = cfn.list_resource_scan_resources(ResourceScanId=scan_id)["Resources"]
    if live_resources:
        sample = live_resources[0]
        live_related = cfn.list_resource_scan_related_resources(
            ResourceScanId=scan_id,
            Resources=[
                {"ResourceType": sample["ResourceType"], "ResourceIdentifier": sample["ResourceIdentifier"]}
            ],
        )
        assert "RelatedResources" in live_related, live_related

    bogus_scan_id = f"arn:aws:cloudformation:{ctx.region}:{account_id}:resourceScan/{uuid.uuid4()}"
    dummy_resources = [
        {
            "ResourceType": "AWS::SNS::Topic",
            "ResourceIdentifier": {"TopicArn": f"arn:aws:sns:{ctx.region}:{account_id}:sim2real-nonexistent"},
        }
    ]

    checks = [
        (
            "DescribeResourceScan",
            "There is no ResourceScan found for the ResourceScanId.",
            lambda: cfn.describe_resource_scan(ResourceScanId=bogus_scan_id),
        ),
        (
            "ListResourceScanRelatedResources",
            "There is no ResourceScan found for the ResourceScanId.",
            lambda: cfn.list_resource_scan_related_resources(
                ResourceScanId=bogus_scan_id, Resources=dummy_resources
            ),
        ),
        (
            "ListResourceScanResources",
            "There is no ResourceScan found for the ResourceScanId.",
            lambda: cfn.list_resource_scan_resources(ResourceScanId=bogus_scan_id),
        ),
    ]
    # Real CloudFormation returns the wire error code "ResourceScanNotFound" (no
    # "Exception" suffix), not the modeled shape name ResourceScanNotFoundException.
    for label, expected, fn in checks:
        code, message = _error(fn)
        assert code == "ResourceScanNotFound", (
            f"{label} returned {code!r}, expected ResourceScanNotFound"
        )
        assert message == expected, f"{label}: expected message {expected!r}, got {message!r}"


def _error(fn):
    """Call fn(); return (code, message) of the ClientError it raises; raise on success."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
