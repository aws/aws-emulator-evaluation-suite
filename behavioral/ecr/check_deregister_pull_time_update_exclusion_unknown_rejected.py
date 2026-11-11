"""deregister-pull-time-update-exclusion-unknown-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deregister-pull-time-update-exclusion-unknown-rejected"
GROUP = "error-semantics"
SERVICES = ["ecr"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:ecr-pull-time-exclusions")
def run(ctx) -> None:
    """DeregisterPullTimeUpdateExclusion for a principalArn that was never registered
    raises ExclusionNotFoundException, and succeeds once the same ARN is registered."""
    ecr = ctx.client("ecr")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    principal_arn = f"arn:aws:iam::{account_id}:role/{ctx.unique_name('sim2real-ecr-excl-')}"

    # Not currently registered anywhere -> deregister must fail.
    code, code_msg = _error(lambda: ecr.deregister_pull_time_update_exclusion(principalArn=principal_arn))
    assert code == "ExclusionNotFoundException", code
    expected_msg = f"The pull time update exclusion for principal arn '{principal_arn}' was not found in registry with id '{ctx.account}'"
    assert code_msg == expected_msg, f"expected message {expected_msg!r}, got {code_msg!r}"

    # Effect-absent: it must not appear in the exclusion list.
    present = _exclusion_present(ecr, principal_arn)
    assert not present, f"expected {principal_arn} absent from exclusion list, but present={present}"

    # Positive control: register it, confirm it is listed, then deregister succeeds.
    ecr.register_pull_time_update_exclusion(principalArn=principal_arn)
    ctx.on_cleanup(lambda: _deregister_safe(ecr, principal_arn))
    present = _exclusion_present(ecr, principal_arn)
    assert present, f"expected {principal_arn} present after register, but present={present}"

    ecr.deregister_pull_time_update_exclusion(principalArn=principal_arn)
    present = _exclusion_present(ecr, principal_arn)
    assert not present, f"expected {principal_arn} absent after deregister, but present={present}"

    # Deletes prove gone AND unusable: deregistering the same ARN a second time must
    # report not-found again, not a silent no-op or a stale success.
    code2, code2_msg = _error(lambda: ecr.deregister_pull_time_update_exclusion(principalArn=principal_arn))
    assert code2 == "ExclusionNotFoundException", f"expected ExclusionNotFoundException on re-deregister, got {code2}"
    expected_msg = f"The pull time update exclusion for principal arn '{principal_arn}' was not found in registry with id '{ctx.account}'"
    assert code2_msg == expected_msg, f"expected message {expected_msg!r}, got {code2_msg!r}"


def _error(fn):
    """Call fn(); return the (code, message) of the ClientError it raises. An unexpected SUCCESS
    raises."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _exclusion_present(ecr, principal_arn: str) -> bool:
    # ListPullTimeUpdateExclusions returns a flat list of principal ARN strings,
    # not objects.
    paginator_resp = ecr.list_pull_time_update_exclusions()
    exclusions = list(paginator_resp.get("pullTimeUpdateExclusions", []))
    next_token = paginator_resp.get("nextToken")
    while next_token:
        page = ecr.list_pull_time_update_exclusions(nextToken=next_token)
        exclusions.extend(page.get("pullTimeUpdateExclusions", []))
        next_token = page.get("nextToken")
    return principal_arn in exclusions


def _deregister_safe(ecr, principal_arn: str) -> None:
    try:
        ecr.deregister_pull_time_update_exclusion(principalArn=principal_arn)
    except ClientError as e:
        if e.response["Error"]["Code"] != "ExclusionNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
