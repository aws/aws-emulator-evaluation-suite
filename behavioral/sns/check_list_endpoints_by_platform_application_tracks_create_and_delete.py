"""list-endpoints-by-platform-application-tracks-create-and-delete."""
from __future__ import annotations

import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-endpoints-by-platform-application-tracks-create-and-delete"
GROUP = "platform-application"
SERVICES = ["sns"]


def _error(fn):
    """(code, message) of the ClientError ``fn`` raises; an unexpected success raises too."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded and returned {result!r}")


def _listed_endpoint_arns(sns, app_arn: str) -> set:
    """Every EndpointArn a paginated ListEndpointsByPlatformApplication walk returns."""
    out = set()
    for page in sns.get_paginator("list_endpoints_by_platform_application").paginate(
        PlatformApplicationArn=app_arn
    ):
        out.update(e["EndpointArn"] for e in page.get("Endpoints", []))
    return out


def _poll(fn, pred, *, timeout_s: float, interval_s: float, description: str):
    """Poll fn() until pred(value) holds; raise AssertionError on timeout."""
    deadline = time.monotonic() + timeout_s
    value = fn()
    while not pred(value):
        if time.monotonic() >= deadline:
            raise AssertionError(f"{description}: condition not met within {timeout_s}s, last saw {value!r}")
        time.sleep(interval_s)
        value = fn()
    return value


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListEndpointsByPlatformApplication reflects an endpoint right after it is created and
    drops it right after it is deleted, while a NextToken SNS never issued is refused.
    """
    sns = ctx.client("sns")

    # BAIDU accepts an arbitrary, unvalidated key pair unlike GCM/ADM, which reject a fabricated
    # credential synchronously.
    app_arn = sns.create_platform_application(
        Name=ctx.unique_name("sim2real-behav-sns-platapp-"),
        Platform="BAIDU",
        Attributes={
            "PlatformPrincipal": ctx.unique_name("baidu-api-key-"),
            "PlatformCredential": ctx.unique_name("baidu-secret-key-"),
        },
    )["PlatformApplicationArn"]
    ctx.on_cleanup(lambda: sns.delete_platform_application(PlatformApplicationArn=app_arn))

    before = _listed_endpoint_arns(sns, app_arn)
    assert before == set(), (
        f"expected a freshly created application to list no endpoints, got {before!r}"
    )

    # Baidu Cloud Push requires a numeric ChannelId that the Token repeats, plus a UserId, or
    # real AWS rejects the create as a blank field.
    channel_id = str(uuid.uuid4().int)[:18]
    endpoint_arn = sns.create_platform_endpoint(
        PlatformApplicationArn=app_arn,
        Token=channel_id,
        Attributes={"ChannelId": channel_id, "UserId": str(uuid.uuid4())},
    )["EndpointArn"]
    ctx.on_cleanup(lambda: sns.delete_endpoint(EndpointArn=endpoint_arn))

    after_create = _poll(
        lambda: _listed_endpoint_arns(sns, app_arn),
        lambda arns: endpoint_arn in arns,
        timeout_s=30.0, interval_s=2.0,
        description="the created endpoint to appear in ListEndpointsByPlatformApplication",
    )
    assert after_create == {endpoint_arn}, (
        f"expected the listing to hold exactly the one endpoint created here, got {after_create!r}"
    )

    # Break exactly one thing: a NextToken SNS never issued.
    code, message = _error(
        lambda: sns.list_endpoints_by_platform_application(
            PlatformApplicationArn=app_arn, NextToken="sim2real-behav-not-a-real-token"
        )
    )
    assert code == "InvalidParameter", f"forged NextToken: expected InvalidParameter, got {code!r}"
    assert message == "Invalid parameter: NextToken Reason: token is invalid or expired", (
        f"unexpected message for a forged NextToken: {message!r}"
    )

    # The rejected call disturbed nothing: the real listing still holds the one endpoint.
    still_there = _listed_endpoint_arns(sns, app_arn)
    assert still_there == {endpoint_arn}, (
        f"the forged-token call must not have changed the listing, got {still_there!r}"
    )

    sns.delete_endpoint(EndpointArn=endpoint_arn)
    after_delete = _poll(
        lambda: _listed_endpoint_arns(sns, app_arn),
        lambda arns: endpoint_arn not in arns,
        timeout_s=30.0, interval_s=2.0,
        description="the deleted endpoint to leave ListEndpointsByPlatformApplication",
    )
    assert after_delete == set(), (
        f"expected the listing to be empty again after the only endpoint was deleted, got {after_delete!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
