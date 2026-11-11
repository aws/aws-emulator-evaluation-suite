"""tag-resource-exceeds-quota-rejected."""
from __future__ import annotations

import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "tag-resource-exceeds-quota-rejected"
GROUP = "error-semantics"
SERVICES = ["acm"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Tagging an ACME endpoint up to the 50-tag quota succeeds; a 51st tag is refused with
    ServiceQuotaExceededException and the exact message and is never persisted."""
    acm = ctx.client("acm")
    endpoint_arn = _create_acme_endpoint(ctx)

    # bring the endpoint to 49 tags (a single TagResource call allows up to 50
    # Tag members, so this fits in one request)
    bulk_tags = [{"Key": f"sim2real-tag-{i}", "Value": "v"} for i in range(49)]
    acm.tag_resource(ResourceArn=endpoint_arn, Tags=bulk_tags)

    # positive control: the 50th tag still fits under the quota
    acm.tag_resource(
        ResourceArn=endpoint_arn, Tags=[{"Key": "sim2real-tag-49", "Value": "v"}]
    )
    at_quota = acm.list_tags_for_resource(ResourceArn=endpoint_arn)["Tags"]
    assert len(at_quota) == 50, f"expected 50 tags at the quota boundary, got {len(at_quota)}"

    def _add_one_more() -> None:
        acm.tag_resource(
            ResourceArn=endpoint_arn, Tags=[{"Key": "sim2real-tag-50", "Value": "v"}]
        )

    code, message = _error_code(_add_one_more)
    assert code == "ServiceQuotaExceededException", (
        f"expected ServiceQuotaExceededException, got {code}"
    )
    assert message == "The resultant tag set must not have more than 50 user tags.", (
        f"expected the exact ServiceQuotaExceededException message AWS returns, got {message!r}"
    )

    # effect absent: the 51st tag was never persisted, count stays at 50
    after = {
        t["Key"]: t["Value"]
        for t in acm.list_tags_for_resource(ResourceArn=endpoint_arn)["Tags"]
    }
    assert len(after) == 50
    assert "sim2real-tag-50" not in after


def _error_code(fn) -> tuple[str, str]:
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"]["Message"]
    raise AssertionError(
        f"expected TagResource to be rejected, but it SUCCEEDED and returned {result!r}"
    )


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
