"""resource-scan-related-resources-unknown-scan-rejected."""
from __future__ import annotations

import time
import uuid
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "resource-scan-related-resources-unknown-scan-rejected"
GROUP = 'resources'
SERVICES = ['cloudformation']

def _related_resources(cf, scan_id, resource):
    return cf.list_resource_scan_related_resources(ResourceScanId=scan_id, Resources=[resource])


def _obtain_complete_scan(cf):
    """Return the id of a COMPLETE resource scan, adopting an existing one or starting one."""
    for s in cf.list_resource_scans().get("ResourceScanSummaries", []):
        if s.get("Status") == "COMPLETE":
            return s["ResourceScanId"]

    try:
        scan_id = cf.start_resource_scan(ScanFilters=[{"Types": ["AWS::SNS::Topic"]}])["ResourceScanId"]
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code")
        if code not in {
            "ResourceScanInProgress", "ResourceScanInProgressException",
            "ResourceScanLimitExceeded", "ResourceScanLimitExceededException",
        }:
            raise
        scans = cf.list_resource_scans().get("ResourceScanSummaries", [])
        assert scans, f"StartResourceScan rejected ({code}) but no existing scan is visible to adopt"
        scan_id = scans[0]["ResourceScanId"]

    deadline = time.monotonic() + 240
    status = None
    while time.monotonic() < deadline:
        status = cf.describe_resource_scan(ResourceScanId=scan_id).get("Status")
        if status == "COMPLETE":
            return scan_id
        if status in {"FAILED", "EXPIRED"}:
            raise AssertionError(f"resource scan {scan_id} ended {status}, expected COMPLETE")
        time.sleep(2)
    raise AssertionError(f"resource scan {scan_id} did not reach COMPLETE within 240s (last={status})")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control", "resource:account-singleton:cfn-resource-scan")
def run(ctx) -> None:
    """ListResourceScanRelatedResources rejects a never-created scan id (standing in for one past
    its 30-day retention) with ResourceScanNotFound; the same call succeeds for a real scan."""
    cf = ctx.client("cloudformation")
    account = ctx.client("sts").get_caller_identity()["Account"]
    dummy_resource = {
        "ResourceType": "AWS::SNS::Topic",
        "ResourceIdentifier": {
            "TopicArn": f"arn:aws:sns:{ctx.region}:{account}:sim2real-behav-nope"
        },
    }

    real_scan_id = _obtain_complete_scan(cf)
    positive = _related_resources(cf, real_scan_id, dummy_resource)
    assert "RelatedResources" in positive, (
        f"positive control failed: ListResourceScanRelatedResources on real COMPLETE "
        f"scan {real_scan_id} returned {positive!r} with no RelatedResources"
    )

    bogus_scan_id = (
        f"arn:aws:cloudformation:{ctx.region}:{account}:"
        f"resourceScan/sim2real-behav-{uuid.uuid4().hex}"
    )
    try:
        result = _related_resources(cf, bogus_scan_id, dummy_resource)
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code")
        message = exc.response.get("Error", {}).get("Message")
    else:
        raise AssertionError(
            f"expected ResourceScanNotFound for unknown scan id {bogus_scan_id!r}, "
            f"call succeeded with {result!r}"
        )
    assert code == "ResourceScanNotFound", (
        f"expected ResourceScanNotFound for unknown scan id, got {code!r}"
    )
    expected = "There is no ResourceScan found for the ResourceScanId."
    assert message == expected, f"expected message {expected!r}, got {message!r}"

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
