"""resource-scan-not-found-error."""
from __future__ import annotations

import uuid

from behavioral_harness import tags

CHECK = "resource-scan-not-found-error"
GROUP = "error-semantics"
SERVICES = ["cloudformation"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DescribeResourceScan on an unknown (but well-formed) scan ARN returns
    the ResourceScanNotFound error code."""
    cfn = ctx.client("cloudformation")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    # Positive control: prove the account/credentials are otherwise healthy for this
    # service before asserting the negative, so the not-found result below cannot be
    # explained by every call to CloudFormation failing.
    control = cfn.list_resource_scans()
    assert "ResourceScanSummaries" in control, (
        f"expected a healthy ListResourceScans response, got {control!r}"
    )

    bogus_scan_id = f"arn:aws:cloudformation:{ctx.region}:{account_id}:resourceScan/{uuid.uuid4()}"

    # Confirmed against real AWS: CloudFormation reports this via the awsQuery error code
    # "ResourceScanNotFound" (no "Exception" suffix), matching the same wire-code family
    # quirk as other CloudFormation not-found errors from this generation of the API
    # (e.g. GeneratedTemplateNotFound, ChangeSetNotFound).
    code, message = _error(lambda: cfn.describe_resource_scan(ResourceScanId=bogus_scan_id))
    assert code == "ResourceScanNotFound", f"expected ResourceScanNotFound, got {code}"
    expected = "There is no ResourceScan found for the ResourceScanId."
    assert message == expected, f"expected message {expected!r}, got {message!r}"


def _error(fn):
    """Call fn(); return (code, message) of the ClientError it raises. An unexpected SUCCESS raises, because
    an emulator ACCEPTING input real AWS refuses is the strongest signal available."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
