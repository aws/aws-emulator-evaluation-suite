"""set-endpoint-attributes-not-found."""
from __future__ import annotations

import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "set-endpoint-attributes-not-found"
GROUP = 'error-semantics'
SERVICES = ['sns']

def _error(fn):
    """Call fn(); return the botocore error (Code, Message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """SetEndpointAttributes on a nonexistent EndpointArn fails with NotFound and the exact message
    'Endpoint does not exist', while the same call on the check's own live endpoint is accepted,
    so the NotFound is specific to the absent endpoint."""
    sns = ctx.client("sns")

    # Baidu Cloud Push ("BAIDU") accepts an arbitrary API-key/secret-key pair with no
    # live/format validation, unlike GCM/ADM which synchronously reject a fabricated
    # credential, so a real, live EndpointArn exists to use as the positive control.
    app_arn = sns.create_platform_application(
        Name=ctx.unique_name("sim2real-behav-platapp-"),
        Platform="BAIDU",
        Attributes={
            "PlatformPrincipal": ctx.unique_name("baidu-api-key-"),
            "PlatformCredential": ctx.unique_name("baidu-secret-key-"),
        },
    )["PlatformApplicationArn"]
    ctx.on_cleanup(lambda: sns.delete_platform_application(PlatformApplicationArn=app_arn))

    # Baidu additionally requires ChannelId and UserId attributes, and the Token
    # field itself must repeat the ChannelId (per the CreatePlatformEndpoint model
    # docs), or real AWS rejects the endpoint creation with a blank-field error.
    # ChannelId must be purely numeric, or real AWS rejects it as malformed.
    channel_id = str(uuid.uuid4().int)[:18]
    real_arn = sns.create_platform_endpoint(
        PlatformApplicationArn=app_arn,
        Token=channel_id,
        Attributes={"ChannelId": channel_id, "UserId": ctx.unique_name("sim2real-behav-user-")},
    )["EndpointArn"]
    ctx.on_cleanup(lambda: sns.delete_endpoint(EndpointArn=real_arn))

    # Positive control: SetEndpointAttributes on the real, just-created endpoint is
    # accepted with no ClientError -- otherwise a target that rejects every
    # SetEndpointAttributes call would pass the negative below for the wrong reason.
    sns.set_endpoint_attributes(EndpointArn=real_arn, Attributes={"Enabled": "false"})

    # Break exactly one thing: derive the bogus ARN by swapping only the real
    # endpoint's own trailing id for a fresh one, keeping every other segment
    # (partition, region, account, platform, app name) intact -- an ARN that
    # merely APPENDS a suffix is malformed and draws InvalidParameter instead of
    # the NotFound this check exists to measure.
    ghost = real_arn.rsplit("/", 1)[0] + "/" + str(uuid.uuid4())
    code, message = _error(
        lambda: sns.set_endpoint_attributes(EndpointArn=ghost, Attributes={"Enabled": "false"})
    )
    assert code == "NotFound", f"SetEndpointAttributes: expected NotFound, got {code}"
    assert message == 'Endpoint does not exist', (
        f"expected the exact message 'Endpoint does not exist', got {message!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
