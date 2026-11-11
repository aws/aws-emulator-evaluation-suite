"""human-readable-summary-unknown-entity-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "human-readable-summary-unknown-entity-rejected"
GROUP = "server-side"
SERVICES = ["iam"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetHumanReadableSummary rejects a nonexistent delegation-request ARN with NoSuchEntity and a
    role ARN (wrong resource type) with ValidationError; an AccessDenied guard rules out a
    blanket denial."""
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-hrs-unknown-role-")
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument='{"Version":"2012-10-17","Statement":[{"Effect":"Allow",'
        '"Principal":{"Service":"ec2.amazonaws.com"},"Action":"sts:AssumeRole"}]}',
        Tags=[{"Key": "sim2real:check", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    account_id = ctx.client("sts").get_caller_identity()["Account"]
    request_id = ctx.unique_name("sim2real-no-such-")
    nonexistent_delegation_arn = f"arn:aws:iam::{account_id}:delegation-request/{request_id}"
    code, message = _error(lambda: iam.get_human_readable_summary(EntityArn=nonexistent_delegation_arn))
    assert code not in ("AccessDenied", "AccessDeniedException"), (
        f"GetHumanReadableSummary is unavailable in this account ({code}); the rejection "
        "differentiation this check asserts cannot be trusted as the documented contract"
    )
    assert code == "NoSuchEntity", (
        f"expected NoSuchEntity for a never-created delegation-request EntityArn, got {code}: {message!r}"
    )
    expected = f"DelegationRequest not found: {request_id}"
    assert message == expected, f"NoSuchEntity message: expected {expected!r}, got {message!r}"

    # Contrast control: a real role ARN is a *different* resource type than delegation-request,
    # and is rejected outright with ValidationError -- it is never silently accepted or treated
    # as a delegation-request entity.
    role_code, role_message = _error(lambda: iam.get_human_readable_summary(EntityArn=role_arn))
    assert role_code == "ValidationError", (
        f"expected ValidationError for a wrong-resource-type EntityArn (role), got {role_code}: "
        f"{role_message!r}"
    )
    expected = "Invalid resource type in ARN"
    assert role_message == expected, (
        f"ValidationError message: expected {expected!r}, got {role_message!r}"
    )


def _error(fn):
    """Call fn(); return its botocore (Error Code, Error Message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
