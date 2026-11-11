"""create-platform-endpoint-nonexistent-app-fails."""
from __future__ import annotations

import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-platform-endpoint-nonexistent-app-fails"
GROUP = 'error-semantics'
SERVICES = ['sns']

def _try_create_endpoint(fn):
    """Call fn(); return (error_code, error_message, endpoint_arn). The code and message are None
    on success, when the endpoint ARN is returned so the caller can clean it up."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message"), None
    return None, None, result.get("EndpointArn")

def _account_id(ctx) -> str:
    """Caller account id (STS, with an SNS-topic-ARN fallback for targets without STS)."""
    try:
        return ctx.client("sts").get_caller_identity()["Account"]
    except Exception:
        sns = ctx.client("sns")
        probe = sns.create_topic(Name=f"sim2real-behav-acctprobe-{uuid.uuid4().hex[:8]}")["TopicArn"]
        try:
            return probe.split(":")[4]
        finally:
            try:
                sns.delete_topic(TopicArn=probe)
            except Exception:
                pass

def _bogus_platform_app_arn(ctx, prefix="sim2real-behav-ghost-app-"):
    """A well-formed but nonexistent PlatformApplicationArn in the caller's account/region."""
    return f"arn:aws:sns:{ctx.region}:{_account_id(ctx)}:app/GCM/{prefix}{uuid.uuid4().hex[:8]}"

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreatePlatformEndpoint under a nonexistent PlatformApplicationArn fails with NotFound,
    while the same call against a real application fails for another reason, never NotFound."""
    sns = ctx.client("sns")

    # BAIDU accepts an arbitrary API-key/secret-key pair at create time; GCM/ADM reject fake
    # credentials and APNS rejects a non-Apple certificate.
    app_arn = sns.create_platform_application(
        Name=ctx.unique_name("sim2real-behav-sns-platapp-"),
        Platform="BAIDU",
        Attributes={
            "PlatformPrincipal": f"baidu-api-key-{uuid.uuid4().hex[:8]}",
            "PlatformCredential": f"baidu-secret-key-{uuid.uuid4().hex[:8]}",
        },
    )["PlatformApplicationArn"]
    ctx.on_cleanup(lambda: sns.delete_platform_application(PlatformApplicationArn=app_arn))

    # Baidu Cloud Push refuses the fabricated token, a reason unrelated to app existence.
    real_app_code, _, real_endpoint_arn = _try_create_endpoint(
        lambda: sns.create_platform_endpoint(
            PlatformApplicationArn=app_arn, Token=f"token-{uuid.uuid4()}"
        )
    )
    if real_endpoint_arn:
        ctx.on_cleanup(lambda: sns.delete_endpoint(EndpointArn=real_endpoint_arn))
    assert real_app_code != "NotFound", (
        f"CreatePlatformEndpoint against a REAL app must not be NotFound, got {real_app_code!r} "
        f"(endpoint_arn={real_endpoint_arn!r})"
    )

    ghost = _bogus_platform_app_arn(ctx)
    ghost_code, ghost_message, ghost_endpoint_arn = _try_create_endpoint(
        lambda: sns.create_platform_endpoint(
            PlatformApplicationArn=ghost, Token=f"token-{uuid.uuid4()}"
        )
    )
    if ghost_endpoint_arn:
        ctx.on_cleanup(lambda: sns.delete_endpoint(EndpointArn=ghost_endpoint_arn))
    assert ghost_code == "NotFound", f"CreatePlatformEndpoint: expected NotFound, got {ghost_code!r}"
    assert ghost_message == "PlatformApplication does not exist", (
        f"unexpected NotFound message for CreatePlatformEndpoint under a missing app: {ghost_message!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
