"""platform-application-not-found."""
from __future__ import annotations

import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "platform-application-not-found"
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

def _fake_platform_application_arn(ctx, name, platform="GCM"):
    return f"arn:aws:sns:{ctx.region}:{_account_id(ctx)}:app/{platform}/{name}"

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetPlatformApplicationAttributes on a well-formed but nonexistent app ARN returns NotFound."""
    ev = ctx.client("sns")
    app_arn = _fake_platform_application_arn(ctx, "nonexistent-fidelity-app")
    code, message = _error(lambda: ev.get_platform_application_attributes(PlatformApplicationArn=app_arn))
    assert code == "NotFound", (
        f"expected NotFound for nonexistent platform application, got {code}"
    )
    expected = 'PlatformApplication does not exist'
    assert message == expected, f"expected message {expected!r}, got {message!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
