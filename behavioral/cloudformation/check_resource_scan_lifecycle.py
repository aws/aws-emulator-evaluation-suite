"""resource-scan-lifecycle."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "resource-scan-lifecycle"
GROUP = "state-machine"
SERVICES = ["cloudformation"]


@tags(
    "axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control",
    "resource:account-singleton:cfn-resource-scan",
)
def run(ctx) -> None:
    """A resource scan reaches COMPLETE and lists an SNS topic created outside CloudFormation by
    its ARN with ManagedByStack false; a related-resources lookup on it returns an empty list."""
    cfn = ctx.client("cloudformation")
    sns = ctx.client("sns")

    topic_name = ctx.unique_name("sim2real-behav-scanlife-")
    topic_arn = sns.create_topic(
        Name=topic_name, Tags=[{"Key": "env", "Value": "test"}, {"Key": "owner", "Value": "fidelity"}]
    )["TopicArn"]
    ctx.on_cleanup(lambda: _delete_topic_if_exists(ctx, topic_arn))

    scan_id = _start_own_scan(ctx, cfn, ScanFilters=[{"Types": ["AWS::SNS::Topic"]}])

    def _status():
        return cfn.describe_resource_scan(ResourceScanId=scan_id)

    # Bounded well under the overall check time limit.
    result = _poll_until(
        _status, lambda r: r["Status"] in ("COMPLETE", "FAILED", "EXPIRED"), timeout_s=200, interval_s=10
    )
    if result["Status"] != "COMPLETE":
        raise AssertionError(
            f"resource scan did not reach COMPLETE within the bounded window (status={result['Status']})"
        )

    summaries = [
        s for page in cfn.get_paginator("list_resource_scans").paginate() for s in page["ResourceScanSummaries"]
    ]
    assert any(s["ResourceScanId"] == scan_id and s["Status"] == "COMPLETE" for s in summaries), summaries

    # The scan reaches COMPLETE before its discovered-resource index is guaranteed queryable.
    match = _poll_until(
        lambda: _find_scanned_topic(cfn, scan_id, topic_arn),
        lambda m: m is not None,
        timeout_s=60,
        interval_s=5,
    )
    assert match is not None, f"resource scan {scan_id} never surfaced {topic_arn} once COMPLETE"
    assert match["ManagedByStack"] is False, match

    related = cfn.list_resource_scan_related_resources(
        ResourceScanId=scan_id,
        Resources=[{"ResourceType": match["ResourceType"], "ResourceIdentifier": match["ResourceIdentifier"]}],
    )["RelatedResources"]
    assert related == [], f"an isolated topic with no subscriptions/policies reported related resources: {related}"


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


def _poll_until(probe, predicate, *, timeout_s=120.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    result = probe()
    while not predicate(result):
        if time.monotonic() >= deadline:
            return result
        time.sleep(interval_s)
        result = probe()
    return result


def _find_scanned_topic(cfn, scan_id: str, topic_arn: str):
    resources = cfn.list_resource_scan_resources(ResourceScanId=scan_id, ResourceTypePrefix="AWS::SNS::Topic")[
        "Resources"
    ]
    return next((r for r in resources if r["ResourceIdentifier"].get("TopicArn") == topic_arn), None)


def _delete_topic_if_exists(ctx, topic_arn: str) -> None:
    sns = ctx.client("sns")
    try:
        sns.delete_topic(TopicArn=topic_arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NotFound":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
