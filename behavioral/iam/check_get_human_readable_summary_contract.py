"""get-human-readable-summary-contract."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-human-readable-summary-contract"
GROUP = "error-semantics"
SERVICES = ["iam"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetHumanReadableSummary: unsupported-entity-type rejection, distinguished from the
    right-type-but-not-found boundary so a target that rejects every call cannot pass by
    accident."""

    iam = ctx.client("iam")

    role_name = ctx.unique_name("sim2real-ghrs-role-")
    trust_policy = (
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow",'
        '"Principal":{"Service":"ec2.amazonaws.com"},"Action":"sts:AssumeRole"}]}'
    )
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=trust_policy,
        Tags=[{"Key": "Purpose", "Value": "sim2real-behavioral"}],
    )
    role_arn = role["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    # Rejection boundary: the only formally supported entity type is
    # "delegation-request". A well-formed ARN for an existing, real entity of a
    # *different* resource type (a role, here) is rejected outright with
    # ValidationError ("Invalid resource type in ARN") rather than resolving to a
    # 200 response with a "not applicable" SummaryState. There is no public API to
    # create a delegation-request entity from this sandbox, so the 200/AVAILABLE
    # success path can't be exercised here; we assert the documented rejection
    # instead.
    try:
        code, message = _error(lambda: iam.get_human_readable_summary(EntityArn=role_arn))
    except AttributeError:
        raise AssertionError("GetHumanReadableSummary not available in installed SDK")
    if code in ("AccessDenied", "AccessDeniedException"):
        raise AssertionError(f"GetHumanReadableSummary unavailable in this account: {code}")
    assert code == "ValidationError", f"expected ValidationError for unsupported entity type ARN, got {code}"
    expected = "Invalid resource type in ARN"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Distinguishing control: a well-formed ARN of the *right* resource type
    # (delegation-request) that simply does not exist must be rejected with the
    # different, specific NoSuchEntity code -- not ValidationError. Without this
    # leg, the assertion above cannot tell "rejects the wrong entity type" from
    # "rejects every EntityArn regardless of type", which is exactly the gap a
    # stub that 400s unconditionally would slip through.
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    missing_id = ctx.unique_name("sim2real-no-such-")
    nonexistent_delegation_arn = f"arn:aws:iam::{account_id}:delegation-request/{missing_id}"
    missing_code, message = _error(
        lambda: iam.get_human_readable_summary(EntityArn=nonexistent_delegation_arn)
    )
    assert missing_code == "NoSuchEntity", (
        f"expected NoSuchEntity for a nonexistent delegation-request EntityArn, got {missing_code}"
    )
    expected = f"DelegationRequest not found: {missing_id}"
    assert message == expected, f"expected message {expected!r}, got {message!r}"


def _error(fn):
    """Call fn(); return (Error.Code, Error.Message) of the ClientError it raises. Raises if fn()
    succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded with {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
