"""tag-resource-nonexistent-resource-rejected."""
from __future__ import annotations

import time
import uuid
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "tag-resource-nonexistent-resource-rejected"
GROUP = "error-semantics"
SERVICES = ["acm"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """TagResource and ListTagsForResource on a nonexistent ACME endpoint ARN are refused with
    ResourceNotFoundException and the exact message, while TagResource on a real endpoint applies
    a tag visible via ListTagsForResource."""
    acm = ctx.client("acm")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]
    fake_arn = (
        f"arn:aws:acm:{ctx.region}:{account_id}:acme-endpoint/{uuid.uuid4()}"
    )

    def _tag_fake():
        return acm.tag_resource(
            ResourceArn=fake_arn, Tags=[{"Key": "sim2real-owner", "Value": "test"}]
        )

    expected = f"Could not find acme-endpoint {fake_arn}."
    code, message = _client_error(_tag_fake)
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code}"
    assert message == expected, f"expected {expected!r}, got {message!r}"

    # effect absent: no tag was created out of thin air -- an independent read against
    # the same never-existed ARN still reports the resource as not found, not as an
    # empty-but-real tag set.
    list_code, list_message = _client_error(lambda: acm.list_tags_for_resource(ResourceArn=fake_arn))
    assert list_code == "ResourceNotFoundException", (
        f"expected the never-existed resource to remain absent, got {list_code}"
    )
    assert list_message == expected, f"expected {expected!r}, got {list_message!r}"

    # positive control: the same TagResource call succeeds on a real endpoint
    endpoint_arn = _create_acme_endpoint(ctx)
    acm.tag_resource(
        ResourceArn=endpoint_arn, Tags=[{"Key": "sim2real-owner", "Value": "test"}]
    )
    tags = {
        t["Key"]: t["Value"]
        for t in acm.list_tags_for_resource(ResourceArn=endpoint_arn)["Tags"]
    }
    assert tags.get("sim2real-owner") == "test"


def _client_error(fn) -> tuple[str, str]:
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _wait_for_endpoint_terminal(
    ctx, arn: str, timeout_s: float = 120.0, interval_s: float = 3.0
) -> dict[str, Any]:
    acm = ctx.client("acm")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        endpoint = acm.describe_acme_endpoint(AcmeEndpointArn=arn)["AcmeEndpoint"]
        if endpoint["Status"] in ("ACTIVE", "FAILED"):
            if endpoint["Status"] != "ACTIVE":
                raise AssertionError(
                    f"endpoint entered FAILED: {endpoint.get('FailureReason')}"
                )
            return endpoint
        time.sleep(interval_s)
    raise AssertionError(f"AcmeEndpoint {arn} stayed CREATING past {timeout_s}s")


def _create_acme_endpoint(ctx) -> str:
    acm = ctx.client("acm")
    arn = acm.create_acme_endpoint(
        AuthorizationBehavior="PRE_APPROVED",
        CertificateAuthority={"PublicCertificateAuthority": {}},
        Contact="NOT_REQUIRED",
    )["AcmeEndpointArn"]
    ctx.on_cleanup(lambda: acm.delete_acme_endpoint(AcmeEndpointArn=arn))
    _wait_for_endpoint_terminal(ctx, arn)
    return arn


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
