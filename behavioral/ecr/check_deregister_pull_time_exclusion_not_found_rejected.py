"""deregister-pull-time-exclusion-not-found-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deregister-pull-time-exclusion-not-found-rejected"
GROUP = "error-semantics"
SERVICES = ["ecr"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:ecr-pull-time-exclusions")
def run(ctx) -> None:
    """DeregisterPullTimeUpdateExclusion on a never-registered principal is refused
    ExclusionNotFoundException with the exact message and lists nothing; once registered it
    deregisters, a repeat is refused the same way, and it can be registered again."""
    ecr = ctx.client("ecr")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]
    principal_arn = f"arn:aws:iam::{account_id}:role/{ctx.unique_name('sim2real-pte-')}"

    code, code_msg = _error(lambda: ecr.deregister_pull_time_update_exclusion(principalArn=principal_arn))
    assert code == "ExclusionNotFoundException", (
        f"expected ExclusionNotFoundException deregistering a never-registered principal, got {code!r}"
    )
    expected_msg = f"The pull time update exclusion for principal arn '{principal_arn}' was not found in registry with id '{ctx.account}'"
    assert code_msg == expected_msg, f"expected message {expected_msg!r}, got {code_msg!r}"

    # Effect absent: it never shows up in the exclusion list.
    assert not _exclusion_present(ecr, principal_arn), (
        f"expected {principal_arn} to be absent from the exclusion list, but it is present"
    )

    # Positive control: registering it, then deregistering, round-trips cleanly.
    ecr.register_pull_time_update_exclusion(principalArn=principal_arn)
    ctx.on_cleanup(lambda: _best_effort_deregister(ecr, principal_arn))
    assert _exclusion_present(ecr, principal_arn), (
        f"expected {principal_arn} to be listed right after registering it"
    )
    ecr.deregister_pull_time_update_exclusion(principalArn=principal_arn)
    assert not _exclusion_present(ecr, principal_arn), (
        f"expected {principal_arn} to be gone from the exclusion list after deregistering"
    )

    # The identifier is dead, not silently ignored: a repeat deregister is rejected the
    # same way as a principal that was never registered at all.
    code_after, code_after_msg = _error(lambda: ecr.deregister_pull_time_update_exclusion(principalArn=principal_arn))
    assert code_after == "ExclusionNotFoundException", (
        f"expected re-deregistering the now-removed principal to raise "
        f"ExclusionNotFoundException, got {code_after!r}"
    )
    expected_msg = f"The pull time update exclusion for principal arn '{principal_arn}' was not found in registry with id '{ctx.account}'"
    assert code_after_msg == expected_msg, f"expected message {expected_msg!r}, got {code_after_msg!r}"

    # ...but the identifier is reusable, not permanently poisoned.
    ecr.register_pull_time_update_exclusion(principalArn=principal_arn)
    assert _exclusion_present(ecr, principal_arn), (
        f"expected {principal_arn} to be listed again after re-registering it"
    )


def _error(fn):
    """Call fn(); return the (code, message) of the ClientError it raises. An unexpected SUCCESS
    raises."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _exclusion_present(ecr, principal_arn):
    next_token = None
    while True:
        kwargs = {"nextToken": next_token} if next_token else {}
        resp = ecr.list_pull_time_update_exclusions(**kwargs)
        for item in resp.get("pullTimeUpdateExclusions", []):
            arn = item["principalArn"] if isinstance(item, dict) else item
            if arn == principal_arn:
                return True
        next_token = resp.get("nextToken")
        if not next_token:
            return False


def _best_effort_deregister(ecr, principal_arn):
    try:
        ecr.deregister_pull_time_update_exclusion(principalArn=principal_arn)
    except ClientError as err:
        if err.response["Error"]["Code"] != "ExclusionNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
