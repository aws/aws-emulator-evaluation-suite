"""list-endpoints-by-nonexistent-application-fails."""
from __future__ import annotations

import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-endpoints-by-nonexistent-application-fails"
GROUP = 'error-semantics'
SERVICES = ['sns']

def _error(fn):
    """Call fn(); return (code, message) of the ClientError it raises. An unexpected success
    raises, so a target that accepts what AWS refuses never reads as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded and returned {result!r}")

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
    """ListEndpointsByPlatformApplication on an unknown application must fail with NotFound."""
    sns = ctx.client("sns")
    ghost = _bogus_platform_app_arn(ctx)
    code, message = _error(
        lambda: sns.list_endpoints_by_platform_application(PlatformApplicationArn=ghost)
    )
    assert code == "NotFound", f"ListEndpointsByPlatformApplication: expected NotFound, got {code}"
    expected = 'PlatformApplication does not exist'
    assert message == expected, f"expected message {expected!r}, got {message!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
