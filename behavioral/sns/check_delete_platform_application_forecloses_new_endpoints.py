"""delete-platform-application-forecloses-new-endpoints."""
from __future__ import annotations

import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-platform-application-forecloses-new-endpoints"
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


def _poll_not_found(fn, *, deadline_s=30.0, poll_s=2.0, description=""):
    """Poll fn() until it raises NotFound; raise on timeout. Read-after-delete is eventually
    consistent, so a bare single read cannot tell a correct target from a lagging one."""
    deadline = time.monotonic() + deadline_s
    last = None
    while True:
        try:
            fn()
            last = "success"
        except ClientError as exc:
            err = exc.response.get("Error", {})
            last = (err.get("Code"), err.get("Message"))
            if last[0] == "NotFound":
                return last
        if time.monotonic() >= deadline:
            raise AssertionError(f"timed out after {deadline_s}s waiting for {description}, last saw {last!r}")
        time.sleep(poll_s)


def _create_app(sns, ctx, name: str) -> str:
    """A BAIDU platform application (accepts an arbitrary, unvalidated key pair, unlike GCM/ADM
    which reject a fabricated credential synchronously); returns its ARN."""
    return sns.create_platform_application(
        Name=name,
        Platform="BAIDU",
        Attributes={
            "PlatformPrincipal": ctx.unique_name("baidu-api-key-"),
            "PlatformCredential": ctx.unique_name("baidu-secret-key-"),
        },
    )["PlatformApplicationArn"]


def _create_endpoint(sns, app_arn: str) -> str:
    """A real endpoint under a BAIDU application. Baidu Cloud Push requires a numeric ChannelId
    that the Token repeats, plus a UserId, or real AWS rejects the create as a blank field."""
    channel_id = str(uuid.uuid4().int)[:18]
    return sns.create_platform_endpoint(
        PlatformApplicationArn=app_arn,
        Token=channel_id,
        Attributes={"ChannelId": channel_id, "UserId": str(uuid.uuid4())},
    )["EndpointArn"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreatePlatformEndpoint and GetPlatformApplicationAttributes both fail NotFound once the
    owning platform application is deleted, while a fresh application of the same name admits
    the identical CreatePlatformEndpoint call.
    """
    sns = ctx.client("sns")
    name = ctx.unique_name("sim2real-behav-sns-platapp-")

    app_arn = _create_app(sns, ctx, name)
    ctx.on_cleanup(lambda: sns.delete_platform_application(PlatformApplicationArn=app_arn))

    # Positive control: the live application admits CreatePlatformEndpoint.
    live_endpoint_arn = _create_endpoint(sns, app_arn)
    ctx.on_cleanup(lambda: sns.delete_endpoint(EndpointArn=live_endpoint_arn))
    attrs = sns.get_platform_application_attributes(PlatformApplicationArn=app_arn)["Attributes"]
    assert attrs.get("Enabled") == "true", (
        f"positive control: expected the live application to report Enabled='true', got {attrs!r}"
    )

    # Break exactly one thing: delete the endpoint, then the application that owned it.
    sns.delete_endpoint(EndpointArn=live_endpoint_arn)
    sns.delete_platform_application(PlatformApplicationArn=app_arn)

    code, message = _poll_not_found(
        lambda: sns.get_platform_application_attributes(PlatformApplicationArn=app_arn),
        description="the deleted application to read back NotFound",
    )
    assert code == "NotFound", f"expected the deleted application to read back NotFound, got {code!r}"
    assert message == "PlatformApplication does not exist", (
        f"unexpected NotFound message reading the deleted application: {message!r}"
    )

    dead_channel_id = str(uuid.uuid4().int)[:18]
    create_code, create_message = _error(
        lambda: sns.create_platform_endpoint(
            PlatformApplicationArn=app_arn,
            Token=dead_channel_id,
            Attributes={"ChannelId": dead_channel_id, "UserId": str(uuid.uuid4())},
        )
    )
    assert create_code == "NotFound", (
        f"CreatePlatformEndpoint under a deleted application: expected NotFound, got {create_code!r}"
    )
    assert create_message == "PlatformApplication does not exist", (
        f"unexpected NotFound message for CreatePlatformEndpoint under a deleted application: {create_message!r}"
    )

    # The NotFound is specific to this now-dead application, not a blanket refusal: a fresh
    # application of the same name admits the identical kind of call.
    fresh_arn = _create_app(sns, ctx, name)
    ctx.on_cleanup(lambda: sns.delete_platform_application(PlatformApplicationArn=fresh_arn))
    fresh_endpoint_arn = _create_endpoint(sns, fresh_arn)
    ctx.on_cleanup(lambda: sns.delete_endpoint(EndpointArn=fresh_endpoint_arn))
    fresh_attrs = sns.get_endpoint_attributes(EndpointArn=fresh_endpoint_arn)["Attributes"]
    assert fresh_attrs.get("Enabled") == "true", (
        f"expected the endpoint under the fresh application to report Enabled='true', got {fresh_attrs!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
