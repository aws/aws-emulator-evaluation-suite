"""deregister-pull-time-update-exclusion-nonexistent-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deregister-pull-time-update-exclusion-nonexistent-rejected"
GROUP = "error-semantics"
SERVICES = ["ecr"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:ecr-pull-time-exclusions")
def run(ctx) -> None:
    """DeregisterPullTimeUpdateExclusion for a principal that was never registered returns
    ExclusionNotFoundException, while a principal that WAS registered deregisters
    successfully exactly once and cannot be deregistered a second time."""
    ecr = ctx.client("ecr")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    never_registered_arn = f"arn:aws:iam::{account_id}:role/{_role_name(ctx, 'never')}"

    err, err_msg = _error(lambda: ecr.deregister_pull_time_update_exclusion(principalArn=never_registered_arn))
    assert err == "ExclusionNotFoundException", f"expected ExclusionNotFoundException, got {err}"
    expected_msg = f"The pull time update exclusion for principal arn '{never_registered_arn}' was not found in registry with id '{ctx.account}'"
    assert err_msg == expected_msg, f"expected message {expected_msg!r}, got {err_msg!r}"

    # Positive control: register then deregister once successfully.
    registered_arn = f"arn:aws:iam::{account_id}:role/{_role_name(ctx, 'reg')}"
    ecr.register_pull_time_update_exclusion(principalArn=registered_arn)
    ctx.on_cleanup(lambda: _safe_deregister(ecr, registered_arn))

    # ListPullTimeUpdateExclusions returns pullTimeUpdateExclusions as a flat list of
    # principalArn strings (not objects), so membership is a plain string comparison.
    exclusions = set(ecr.list_pull_time_update_exclusions()["pullTimeUpdateExclusions"])
    assert registered_arn in exclusions, f"expected {registered_arn} in {exclusions}"

    ecr.deregister_pull_time_update_exclusion(principalArn=registered_arn)
    exclusions_after = set(ecr.list_pull_time_update_exclusions()["pullTimeUpdateExclusions"])
    assert registered_arn not in exclusions_after, f"expected {registered_arn} absent from {exclusions_after}"

    # Deregistering it again now that it's gone is rejected, not a silent no-op.
    err2, err2_msg = _error(lambda: ecr.deregister_pull_time_update_exclusion(principalArn=registered_arn))
    assert err2 == "ExclusionNotFoundException", f"expected ExclusionNotFoundException on re-deregister, got {err2}"
    expected_msg = f"The pull time update exclusion for principal arn '{registered_arn}' was not found in registry with id '{ctx.account}'"
    assert err2_msg == expected_msg, f"expected message {expected_msg!r}, got {err2_msg!r}"


def _role_name(ctx, suffix: str) -> str:
    raw = ctx.unique_name(f"sim2real-excl-{suffix}-")
    raw = "".join(c for c in raw if c.isalnum() or c in "+=,.@-")
    return raw[:60]


def _error(fn):
    """Call fn(); return the (code, message) of the ClientError it raises. An unexpected SUCCESS
    raises."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _safe_deregister(ecr, arn):
    try:
        ecr.deregister_pull_time_update_exclusion(principalArn=arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ExclusionNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
