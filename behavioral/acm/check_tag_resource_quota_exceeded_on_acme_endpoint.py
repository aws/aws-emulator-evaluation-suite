"""tag-resource-quota-exceeded-on-acme-endpoint."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "tag-resource-quota-exceeded-on-acme-endpoint"
GROUP = "error-semantics"
SERVICES = ["acm"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """TagResource on an ACME endpoint at the 50-tag quota is refused with
    ServiceQuotaExceededException and the exact message and persists nothing; after one untag the
    identical call succeeds, so the refusal tracks the live tag count."""
    acm = ctx.client("acm")
    arn = _create_acme_endpoint(ctx)

    fill_tags = [{"Key": f"sim2real-quota-{i}", "Value": str(i)} for i in range(50)]
    acm.tag_resource(ResourceArn=arn, Tags=fill_tags)
    tags_after_fill = acm.list_tags_for_resource(ResourceArn=arn)["Tags"]
    assert len(tags_after_fill) == 50, (
        f"positive control: expected exactly 50 tags after filling to the quota, got {len(tags_after_fill)}"
    )

    extra_key = "sim2real-quota-overflow"
    code, message = _client_error(
        lambda: acm.tag_resource(ResourceArn=arn, Tags=[{"Key": extra_key, "Value": "x"}])
    )
    assert code == "ServiceQuotaExceededException", (
        f"expected ServiceQuotaExceededException tagging past the 50-tag quota, got {code!r}"
    )
    expected = "The resultant tag set must not have more than 50 user tags."
    assert message == expected, f"expected {expected!r}, got {message!r}"

    tags_final = acm.list_tags_for_resource(ResourceArn=arn)["Tags"]
    assert len(tags_final) == 50, (
        f"rejected tag must not be persisted: expected count to remain 50, got {len(tags_final)}"
    )
    assert all(t["Key"] != extra_key for t in tags_final), (
        f"rejected key {extra_key!r} must not appear among the resource's tags"
    )

    # Restore: untag one entry to drop back below the quota, then re-issue the
    # identical call that was just rejected and demand it now succeeds.
    acm.untag_resource(ResourceArn=arn, TagKeys=["sim2real-quota-0"])
    tags_after_untag = acm.list_tags_for_resource(ResourceArn=arn)["Tags"]
    assert len(tags_after_untag) == 49, (
        f"expected 49 tags after untagging one entry, got {len(tags_after_untag)}"
    )

    acm.tag_resource(ResourceArn=arn, Tags=[{"Key": extra_key, "Value": "x"}])
    tags_after_restore = acm.list_tags_for_resource(ResourceArn=arn)["Tags"]
    tag_map_after_restore = {t["Key"]: t["Value"] for t in tags_after_restore}
    assert len(tags_after_restore) == 50, (
        f"once back under quota, the identical call must succeed: expected 50 tags, got {len(tags_after_restore)}"
    )
    assert tag_map_after_restore.get(extra_key) == "x", (
        f"expected {extra_key!r}='x' present after the identical call succeeded, got {tag_map_after_restore.get(extra_key)!r}"
    )


def _client_error(fn):
    """Call fn(); return its botocore error (code, message). A success raises: accepting a call AWS refuses is a
    mismatch of its own, not a wrong error code."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected rejection but the call SUCCEEDED and returned {result!r}")


def _create_acme_endpoint(ctx, contact: str = "NOT_REQUIRED") -> str:
    acm = ctx.client("acm")
    resp = acm.create_acme_endpoint(
        AuthorizationBehavior="PRE_APPROVED",
        CertificateAuthority={"PublicCertificateAuthority": {}},
        Contact=contact,
    )
    arn = resp["AcmeEndpointArn"]
    ctx.on_cleanup(lambda: _delete_endpoint(ctx, arn))
    status = _wait_for_endpoint_terminal(ctx, arn)
    if status != "ACTIVE":
        raise AssertionError(f"AcmeEndpoint {arn} settled in status {status}, expected ACTIVE")
    return arn


def _wait_for_endpoint_terminal(ctx, arn: str, timeout_s: float = 120.0, interval_s: float = 3.0) -> str:
    acm = ctx.client("acm")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = acm.describe_acme_endpoint(AcmeEndpointArn=arn)["AcmeEndpoint"]["Status"]
        if last in ("ACTIVE", "FAILED"):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"AcmeEndpoint {arn} never left a non-terminal status; last={last}")


def _delete_endpoint(ctx, arn: str) -> None:
    """Teardown: delete the endpoint, retrying the documented ConflictException while it is still
    settling; an endpoint that is already gone is accepted, anything else raises."""
    from botocore.exceptions import ClientError

    acm = ctx.client("acm")
    deadline = time.monotonic() + min(120.0, ctx.time_left() or 120.0)
    while True:
        try:
            acm.delete_acme_endpoint(AcmeEndpointArn=arn)
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "ResourceNotFoundException":
                return
            if code != "ConflictException" or time.monotonic() >= deadline:
                raise
        time.sleep(2.0)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
