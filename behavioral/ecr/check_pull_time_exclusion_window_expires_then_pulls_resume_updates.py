"""pull-time-exclusion-window-expires-then-pulls-resume-updates."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "pull-time-exclusion-window-expires-then-pulls-resume-updates"
GROUP = "visibility-timeout-ttl"
SERVICES = ["ecr"]

# RegisterPullTimeUpdateExclusion's request/response shape carries only `principalArn`
# (plus `createdAt` on the response) - there is no TTL/duration field on real AWS
# (see API_RegisterPullTimeUpdateExclusion). So real ECR does not auto-expire an
# exclusion on its own "window": it stays active indefinitely until an explicit
# DeregisterPullTimeUpdateExclusion call. This check asserts exactly that real
# behavior - persistence across a later registration, then removal only on explicit
# action - which catches an emulator that either (a) drops the exclusion before it is
# deregistered, or (b) fails to actually remove it once DeregisterPullTimeUpdateExclusion
# is called.


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:ecr-pull-time-exclusions")
def run(ctx) -> None:
    """A registered pull-time-update exclusion has no auto-expiring window: it remains
    present after a later registration and disappears only once explicitly deregistered,
    while the later exclusion stays."""
    ecr = ctx.client("ecr")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    role_name = ctx.unique_name("sim2real-ecr-window-").replace("_", "-")
    principal_arn = f"arn:aws:iam::{account_id}:role/{role_name}"

    ecr.register_pull_time_update_exclusion(principalArn=principal_arn)
    ctx.on_cleanup(lambda: _best_effort_deregister(ecr, principal_arn))

    assert _is_registered(ecr, principal_arn), (
        "exclusion is not listed immediately after RegisterPullTimeUpdateExclusion"
    )

    # A later registration is the contrast: the first exclusion is still listed beside it.
    control_arn = f"arn:aws:iam::{account_id}:role/{role_name}-control"
    ecr.register_pull_time_update_exclusion(principalArn=control_arn)
    ctx.on_cleanup(lambda: _best_effort_deregister(ecr, control_arn))
    listed = _list_all_exclusions(ecr)
    assert principal_arn in listed and control_arn in listed, (
        f"after a second registration both exclusions must be listed, "
        f"got {[a for a in listed if a in (principal_arn, control_arn)]!r}"
    )

    # Now remove it explicitly, and confirm removal actually takes effect - the only
    # way this exclusion goes away is via this explicit call.
    ecr.deregister_pull_time_update_exclusion(principalArn=principal_arn)
    listed = _list_all_exclusions(ecr)
    assert principal_arn not in listed, (
        "exclusion is still listed immediately after an explicit Deregister call"
    )
    assert control_arn in listed, (
        "deregistering one exclusion removed the other registered exclusion as well"
    )

    # The dead principal is now unusable for the same mutation: a second Deregister
    # for it must fail with the specific not-found error, not silently succeed again.
    try:
        ecr.deregister_pull_time_update_exclusion(principalArn=principal_arn)
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        assert code == "ExclusionNotFoundException", (
            f"expected ExclusionNotFoundException on a repeat Deregister of an "
            f"already-removed principal, got {code}"
        )
        message = exc.response["Error"].get("Message")
        expected_message = (
            f"The pull time update exclusion for principal arn '{principal_arn}' was not found "
            f"in registry with id '{account_id}'"
        )
        assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"
    else:
        raise AssertionError(
            "a second DeregisterPullTimeUpdateExclusion call on the same "
            "already-removed principal succeeded instead of raising "
            "ExclusionNotFoundException"
        )


def _list_all_exclusions(ecr) -> list[dict]:
    out: list[dict] = []
    token = None
    while True:
        kwargs = {"nextToken": token} if token else {}
        resp = ecr.list_pull_time_update_exclusions(**kwargs)
        out.extend(resp.get("pullTimeUpdateExclusions", []))
        token = resp.get("nextToken")
        if not token:
            break
    return out


def _is_registered(ecr, principal_arn: str) -> bool:
    return principal_arn in _list_all_exclusions(ecr)


def _best_effort_deregister(ecr, principal_arn: str) -> None:
    try:
        ecr.deregister_pull_time_update_exclusion(principalArn=principal_arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ExclusionNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
