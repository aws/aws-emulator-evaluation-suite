"""resource-scan-result-ttl-expiry."""
from __future__ import annotations

import time
import uuid
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "resource-scan-result-ttl-expiry"
GROUP = 'resource_scans'
SERVICES = ['cloudformation']


def _error(fn):
    """Call fn(); return (Error.Code, Error.Message) of the ClientError it raises. An unexpected
    success raises, so an emulator accepting what AWS refuses never reads as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")

def _wait_resource_scan(cf, scan_id, timeout_s=600, interval_s=10):
    """Poll DescribeResourceScan until Status is terminal; return the response."""
    deadline = time.monotonic() + timeout_s
    resp = None
    while time.monotonic() < deadline:
        resp = cf.describe_resource_scan(ResourceScanId=scan_id)
        if resp.get("Status") in {"COMPLETE", "FAILED", "EXPIRED"}:
            return resp
        time.sleep(interval_s)
    raise AssertionError(f"resource scan {scan_id} did not settle (last={resp!r})")


def _start_own_scan(cf):
    """Start this check's own SNS-filtered scan, created after the topic so its results must
    include it. Only one scan may run per account at a time, so an in-progress scan is first
    waited out rather than adopted."""
    filters = [{"Types": ["AWS::SNS::Topic"]}]
    try:
        return cf.start_resource_scan(ScanFilters=filters)["ResourceScanId"]
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceScanInProgress":
            raise
    for s in cf.list_resource_scans().get("ResourceScanSummaries", []):
        if s.get("Status") == "IN_PROGRESS":
            _wait_resource_scan(cf, s["ResourceScanId"], timeout_s=900, interval_s=15)
    return cf.start_resource_scan(ScanFilters=filters)["ResourceScanId"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control", "resource:account-singleton:cfn-resource-scan")
def run(ctx) -> None:
    """ListResourceScanResources is gated by scan state and lists the new topic once COMPLETE.

    It is ResourceScanInProgress when the scan is observed IN_PROGRESS, and a never-created scan
    id is ResourceScanNotFound on both ListResourceScanResources and DescribeResourceScan.
    """
    cf = ctx.client("cloudformation")
    sns = ctx.client("sns")
    topic_name = ctx.unique_name("sim2real-behav-scan-topic-")
    topic_arn = sns.create_topic(
        Name=topic_name, Tags=[{"Key": "sim2real-check", "Value": CHECK}]
    )["TopicArn"]
    ctx.on_cleanup(lambda: sns.delete_topic(TopicArn=topic_arn))

    scan_id = _start_own_scan(cf)

    # While the scan is (very likely) still IN_PROGRESS immediately after
    # starting it, results must not be visible yet.
    current_status = cf.describe_resource_scan(ResourceScanId=scan_id)["Status"]
    if current_status == "IN_PROGRESS":
        gate_code, gate_message = _error(lambda: cf.list_resource_scan_resources(ResourceScanId=scan_id))
        assert gate_code == "ResourceScanInProgress", gate_code
        expected = (
            "The ResourceScan is in progress. Please wait for it to finish before performing any "
            "further operations on it. Describe ResourceScans to see the status of the in-progress "
            "ResourceScan."
        )
        assert gate_message == expected, f"expected message {expected!r}, got {gate_message!r}"

    desc = _wait_resource_scan(cf, scan_id, timeout_s=600, interval_s=10)
    assert desc["Status"] == "COMPLETE", desc.get("StatusReason")

    # Once genuinely COMPLETE, results become visible -- and must actually contain the
    # SNS topic this check just created, not merely echo an empty/absent collection.
    resp = cf.list_resource_scan_resources(ResourceScanId=scan_id)
    resources = resp["Resources"]
    assert any(
        r["ResourceType"] == "AWS::SNS::Topic"
        and r["ResourceIdentifier"].get("TopicArn") == topic_arn
        for r in resources
    ), f"expected {topic_arn} among scanned AWS::SNS::Topic resources, got {resources!r}"

    # Overly-permissive boundary: an entirely unknown/never-existed scan id
    # (standing in for one past its retention TTL) must be rejected, not
    # silently return empty/success.
    account = ctx.client("sts").get_caller_identity()["Account"]
    bogus_scan_id = (
        f"arn:aws:cloudformation:{ctx.region}:{account}:"
        f"resourceScan/sim2real-behav-{uuid.uuid4().hex}"
    )
    code_bogus, message_bogus = _error(lambda: cf.list_resource_scan_resources(ResourceScanId=bogus_scan_id))
    assert code_bogus == "ResourceScanNotFound", code_bogus
    expected = "There is no ResourceScan found for the ResourceScanId."
    assert message_bogus == expected, f"expected message {expected!r}, got {message_bogus!r}"

    code_bogus2, message_bogus2 = _error(lambda: cf.describe_resource_scan(ResourceScanId=bogus_scan_id))
    assert code_bogus2 == "ResourceScanNotFound", code_bogus2
    expected = "There is no ResourceScan found for the ResourceScanId."
    assert message_bogus2 == expected, f"expected message {expected!r}, got {message_bogus2!r}"

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
