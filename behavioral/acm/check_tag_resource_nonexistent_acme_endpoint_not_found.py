"""tag-resource-nonexistent-acme-endpoint-not-found."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "tag-resource-nonexistent-acme-endpoint-not-found"
GROUP = "error-semantics"
SERVICES = ["acm"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """TagResource against a deleted ACME endpoint ARN raises ResourceNotFoundException, not a silent no-op."""
    acm = ctx.client("acm")
    endpoint_arn = _create_acme_endpoint(ctx)
    _wait_for_endpoint_status(ctx, endpoint_arn, {"ACTIVE"})
    acm.delete_acme_endpoint(AcmeEndpointArn=endpoint_arn)
    _wait_for_endpoint_gone(ctx, endpoint_arn)

    expected = f"Could not find acme-endpoint {endpoint_arn}."
    code, message = _expect_error(
        lambda: acm.tag_resource(ResourceArn=endpoint_arn, Tags=[{"Key": "sim2real", "Value": "x"}])
    )
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code!r}"
    assert message == expected, f"expected {expected!r}, got {message!r}"

    # effect absent: there is nothing to tag -- the resource itself remains not found
    list_code, list_message = _expect_error(lambda: acm.list_tags_for_resource(ResourceArn=endpoint_arn))
    assert list_code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {list_code!r}"
    assert list_message == expected, f"expected {expected!r}, got {list_message!r}"

    # positive control: tagging a live endpoint succeeds and the tag is observable
    live_arn = _create_acme_endpoint(ctx)
    _wait_for_endpoint_status(ctx, live_arn, {"ACTIVE"})
    acm.tag_resource(ResourceArn=live_arn, Tags=[{"Key": "sim2real", "Value": "x"}])
    live_tags = acm.list_tags_for_resource(ResourceArn=live_arn)["Tags"]
    assert {"Key": "sim2real", "Value": "x"} in live_tags, f"expected sim2real tag in {live_tags!r}"


def _expect_error(fn):
    """Return (code, message) of the ClientError fn raises; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _create_acme_endpoint(ctx):
    acm = ctx.client("acm")
    resp = acm.create_acme_endpoint(
        AuthorizationBehavior="PRE_APPROVED",
        CertificateAuthority={"PublicCertificateAuthority": {}},
    )
    arn = resp["AcmeEndpointArn"]
    ctx.on_cleanup(lambda: _delete_acme_endpoint(ctx, arn))
    return arn


def _delete_acme_endpoint(ctx, arn):
    acm = ctx.client("acm")
    acm.delete_acme_endpoint(AcmeEndpointArn=arn)


def _wait_for_endpoint_status(ctx, arn, target_statuses, timeout_s=90.0, interval_s=3.0):
    acm = ctx.client("acm")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = acm.describe_acme_endpoint(AcmeEndpointArn=arn)["AcmeEndpoint"]["Status"]
        if last in target_statuses:
            return last
        time.sleep(interval_s)
    raise AssertionError(f"endpoint {arn} never reached {target_statuses}, last status {last!r}")


def _wait_for_endpoint_gone(ctx, arn, timeout_s=90.0, interval_s=3.0):
    acm = ctx.client("acm")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            acm.describe_acme_endpoint(AcmeEndpointArn=arn)
        except ClientError as err:
            if err.response["Error"]["Code"] == "ResourceNotFoundException":
                return
        time.sleep(interval_s)
    raise AssertionError(f"endpoint {arn} was never fully removed within {timeout_s}s")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
