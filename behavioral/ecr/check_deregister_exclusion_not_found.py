"""deregister-exclusion-not-found."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deregister-exclusion-not-found"
GROUP = "error-semantics"
SERVICES = ["ecr"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control", "resource:account-singleton:ecr-pull-time-exclusions")
def run(ctx) -> None:
    """DeregisterPullTimeUpdateExclusion on a never-registered principal is refused
    ExclusionNotFoundException with the exact message; a registered principal is listed,
    deregisters, is refused the same way on a repeat, and can be registered again."""
    ecr = ctx.client("ecr")
    account_id = ctx.client("sts").get_caller_identity()["Account"]

    never_registered = (
        f"arn:aws:iam::{account_id}:role/{ctx.unique_name('sim2real-ecr-never-')}"
    )
    code, code_msg = _error(
        lambda: ecr.deregister_pull_time_update_exclusion(principalArn=never_registered)
    )
    assert code == "ExclusionNotFoundException", (
        f"expected ExclusionNotFoundException deregistering a never-registered "
        f"principal, got {code!r}"
    )
    expected_msg = f"The pull time update exclusion for principal arn '{never_registered}' was not found in registry with id '{ctx.account}'"
    assert code_msg == expected_msg, f"expected message {expected_msg!r}, got {code_msg!r}"

    # positive control: register then deregister a fresh principal successfully
    registered = f"arn:aws:iam::{account_id}:role/{ctx.unique_name('sim2real-ecr-reg-')}"
    ecr.register_pull_time_update_exclusion(principalArn=registered)
    ctx.on_cleanup(lambda: _best_effort_deregister(ecr, registered))

    assert registered in _list_exclusions(ecr), (
        f"expected {registered} to be listed right after registering it"
    )

    resp = ecr.deregister_pull_time_update_exclusion(principalArn=registered)
    assert resp["principalArn"] == registered, (
        f"expected deregister response to echo {registered}, got {resp.get('principalArn')!r}"
    )

    # terminal read is independent of the mutating call: the exclusion list itself,
    # not the deregister response, is what proves the removal took effect
    remaining = _list_exclusions(ecr)
    assert registered not in remaining, (
        f"expected {registered} to be gone from the exclusion list after "
        f"deregistering, still present in {remaining}"
    )

    # the identifier is dead, not silently ignored: a repeat deregister is rejected
    # the same way as a principal that was never registered at all
    code_after, code_after_msg = _error(
        lambda: ecr.deregister_pull_time_update_exclusion(principalArn=registered)
    )
    assert code_after == "ExclusionNotFoundException", (
        f"expected re-deregistering the now-removed principal to raise "
        f"ExclusionNotFoundException, got {code_after!r}"
    )
    expected_msg = f"The pull time update exclusion for principal arn '{registered}' was not found in registry with id '{ctx.account}'"
    assert code_after_msg == expected_msg, f"expected message {expected_msg!r}, got {code_after_msg!r}"

    # ...but the identifier is reusable, not permanently poisoned
    resp_again = ecr.register_pull_time_update_exclusion(principalArn=registered)
    assert resp_again["principalArn"] == registered, (
        f"expected re-registering {registered} to succeed, got {resp_again!r}"
    )
    assert registered in _list_exclusions(ecr), (
        f"expected {registered} to be listed again after re-registering it"
    )


def _error(fn):
    """Call fn(); return the (code, message) of the ClientError it raises. An unexpected SUCCESS
    raises."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _list_exclusions(ecr):
    exclusions = []
    next_token = None
    while True:
        kwargs = {"nextToken": next_token} if next_token else {}
        resp = ecr.list_pull_time_update_exclusions(**kwargs)
        exclusions.extend(resp.get("pullTimeUpdateExclusions", []))
        next_token = resp.get("nextToken")
        if not next_token:
            return exclusions


def _best_effort_deregister(ecr, principal_arn):
    try:
        ecr.deregister_pull_time_update_exclusion(principalArn=principal_arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ExclusionNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
