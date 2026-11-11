"""delete-platform-application-nonexistent-idempotent."""
from __future__ import annotations

import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-platform-application-nonexistent-idempotent"
GROUP = 'platform-application'
SERVICES = ['sns']

def _error(fn):
    """(Code, Message) of the ClientError fn() raises; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")

def _poll_until_not_found(fn, deadline_s=30.0, poll_s=2.0, description=""):
    """Poll fn() until it raises NotFound; raise on timeout."""
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
            raise AssertionError(
                f"timed out after {deadline_s}s waiting for {description}, last saw {last!r}"
            )
        time.sleep(poll_s)

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

@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeletePlatformApplication is idempotent: repeating it on a just-deleted app and calling it
    on a never-created ARN are both no-ops, and neither app is readable afterwards."""
    sns = ctx.client("sns")

    # BAIDU accepts an arbitrary API-key/secret-key pair with no live credential validation.

    app_arn = sns.create_platform_application(
        Name=ctx.unique_name("sim2real-behav-platapp-"),
        Platform="BAIDU",
        Attributes={
            "PlatformPrincipal": ctx.unique_name("baidu-api-key-"),
            "PlatformCredential": ctx.unique_name("baidu-secret-key-"),
        },
    )["PlatformApplicationArn"]
    ctx.on_cleanup(lambda: sns.delete_platform_application(PlatformApplicationArn=app_arn))

    attrs = sns.get_platform_application_attributes(PlatformApplicationArn=app_arn)["Attributes"]
    assert attrs, f"expected a freshly-created platform application to be readable, got {attrs}"

    sns.delete_platform_application(PlatformApplicationArn=app_arn)

    # Read-after-delete is eventually consistent: Get can still succeed for a few seconds.
    code, message = _poll_until_not_found(
        lambda: sns.get_platform_application_attributes(PlatformApplicationArn=app_arn),
        description="the deleted app to read back NotFound",
    )
    assert code == "NotFound", f"expected the deleted app to read back NotFound, got {code}"
    assert message == "PlatformApplication does not exist", (
        f"unexpected NotFound message reading the deleted app: {message!r}"
    )

    sns.delete_platform_application(PlatformApplicationArn=app_arn)

    ghost = _bogus_platform_app_arn(ctx)
    sns.delete_platform_application(PlatformApplicationArn=ghost)

    code, message = _error(lambda: sns.get_platform_application_attributes(PlatformApplicationArn=ghost))
    assert code == "NotFound", (
        f"deleting a never-created app should not create it as a side effect, get returned {code}"
    )
    assert message == "PlatformApplication does not exist", (
        f"unexpected NotFound message reading a never-created app: {message!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
