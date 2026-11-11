"""deregister-pull-time-update-exclusion-not-found-rejected."""
from __future__ import annotations

import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deregister-pull-time-update-exclusion-not-found-rejected"
GROUP = "error-semantics"
SERVICES = ["ecr"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control", "resource:account-singleton:ecr-pull-time-exclusions")
def run(ctx) -> None:
    """Deregistering a non-existent pull-time update exclusion returns
    ExclusionNotFoundException, while register->deregister on a real principal in the
    same file succeeds (control)."""
    ecr = ctx.client("ecr")
    account_id = ctx.client("sts").get_caller_identity()["Account"]

    unregistered_arn = (
        f"arn:aws:iam::{account_id}:role/sim2real-ecr-never-registered-{uuid.uuid4().hex[:10]}"
    )

    # negative
    code, code_msg = _error(
        lambda: ecr.deregister_pull_time_update_exclusion(principalArn=unregistered_arn)
    )
    assert code == "ExclusionNotFoundException", code
    expected_msg = f"The pull time update exclusion for principal arn '{unregistered_arn}' was not found in registry with id '{ctx.account}'"
    assert code_msg == expected_msg, f"expected message {expected_msg!r}, got {code_msg!r}"

    # effect absent: it never shows up in the exclusion list either.
    assert not _exclusion_present(ecr, unregistered_arn), "unregistered principal appeared in list"

    # positive control: register a real principal then deregister it successfully
    registered_arn = (
        f"arn:aws:iam::{account_id}:role/sim2real-ecr-control-{uuid.uuid4().hex[:10]}"
    )
    ecr.register_pull_time_update_exclusion(principalArn=registered_arn)

    def _cleanup():
        try:
            ecr.deregister_pull_time_update_exclusion(principalArn=registered_arn)
        except ClientError as e:
            if e.response["Error"]["Code"] != "ExclusionNotFoundException":
                raise

    ctx.on_cleanup(_cleanup)

    # independent read: registration is really visible before we tear it down.
    assert _exclusion_present(ecr, registered_arn), "registered principal missing from list"

    ecr.deregister_pull_time_update_exclusion(principalArn=registered_arn)  # must not raise

    # independent read: the destination confirms it is really gone.
    assert not _exclusion_present(ecr, registered_arn), "deregistered principal still listed"

    # deregistering it a second time now correctly reports not-found again
    code_after_control, code_after_control_msg = _error(
        lambda: ecr.deregister_pull_time_update_exclusion(principalArn=registered_arn)
    )
    assert code_after_control == "ExclusionNotFoundException", code_after_control
    expected_msg = f"The pull time update exclusion for principal arn '{registered_arn}' was not found in registry with id '{ctx.account}'"
    assert code_after_control_msg == expected_msg, f"expected message {expected_msg!r}, got {code_after_control_msg!r}"


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
        if principal_arn in resp.get("pullTimeUpdateExclusions", []):
            return True
        next_token = resp.get("nextToken")
        if not next_token:
            return False


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
