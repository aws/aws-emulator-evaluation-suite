"""describe-resource-scan-not-found-error."""
from __future__ import annotations

import time
import uuid

from behavioral_harness import tags

CHECK = "describe-resource-scan-not-found-error"
GROUP = "error-semantics"
SERVICES = ["cloudformation"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control", "resource:account-singleton:cfn-resource-scan")
def run(ctx) -> None:
    """DescribeResourceScan with an unknown scan ARN fails with ResourceScanNotFound "There is no
    ResourceScan found for the ResourceScanId.", while DescribeResourceScan on an existing scan id
    succeeds."""
    cfn = ctx.client("cloudformation")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    real_scan_id = _adopt_or_start_scan(cfn)
    positive = cfn.describe_resource_scan(ResourceScanId=real_scan_id)
    assert positive["ResourceScanId"] == real_scan_id, (
        f"positive control failed: describing real scan id {real_scan_id} returned {positive}"
    )

    bogus_arn = (
        f"arn:aws:cloudformation:{ctx.region}:{account_id}:resourceScan/{uuid.uuid4()}"
    )
    err = _expect_error(lambda: cfn.describe_resource_scan(ResourceScanId=bogus_arn)).response["Error"]
    # Real AWS returns the wire error code "ResourceScanNotFound" (no "Exception" suffix) --
    # distinct from the modeled botocore exception class name ResourceScanNotFoundException.
    assert err["Code"] == "ResourceScanNotFound", (
        f"expected ResourceScanNotFound, got {err['Code']}"
    )
    expected_message = "There is no ResourceScan found for the ResourceScanId."
    assert err.get("Message") == expected_message, (
        f"expected message {expected_message!r}, got {err.get('Message')!r}"
    )


def _adopt_or_start_scan(cfn) -> str:
    """A real resource-scan id to describe as the positive control. Uses an existing scan if
    the account has one (resource scans cannot be deleted and expire after 30 days); otherwise
    starts one, falling back to a listed scan when another scan holds the StartResourceScan limit."""
    from botocore.exceptions import ClientError

    summaries = cfn.list_resource_scans().get("ResourceScanSummaries", [])
    if summaries:
        return summaries[0]["ResourceScanId"]

    deadline = time.monotonic() + 15
    while True:
        try:
            return cfn.start_resource_scan()["ResourceScanId"]
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "ThrottlingException" and time.monotonic() < deadline:
                time.sleep(2)
                continue
            if code in (
                "ResourceScanInProgressException",
                "ResourceScanInProgress",
                "ResourceScanLimitExceededException",
                "ResourceScanLimitExceeded",
            ):
                summaries = cfn.list_resource_scans().get("ResourceScanSummaries", [])
                if summaries:
                    return summaries[0]["ResourceScanId"]
            raise


def _expect_error(fn):
    """Call fn(); return the raised ClientError. Raise if fn() succeeds unexpectedly."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
