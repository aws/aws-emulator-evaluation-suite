"""pull-time-update-exclusion-window-expires."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "pull-time-update-exclusion-window-expires"
GROUP = "visibility-timeout-ttl"
SERVICES = ["ecr"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:ecr-pull-time-exclusions")
def run(ctx) -> None:
    """A registered pull-time update exclusion stays listed at every one of at least three polls
    (the API has no expiry), is gone after DeregisterPullTimeUpdateExclusion, and a repeat
    deregister is refused ExclusionNotFoundException with the exact message."""
    ecr = ctx.client("ecr")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]
    principal_arn = f"arn:aws:iam::{account_id}:role/{ctx.unique_name('sim2real-ecr-pte-ttl-')}"

    ecr.register_pull_time_update_exclusion(principalArn=principal_arn)

    def _safe_deregister() -> None:
        try:
            ecr.deregister_pull_time_update_exclusion(principalArn=principal_arn)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ExclusionNotFoundException":
                raise

    ctx.on_cleanup(_safe_deregister)

    assert _is_present(ecr, principal_arn), "exclusion missing immediately after registration"

    # Poll across a bounded window (no deregistration happens during this loop): the
    # exclusion must remain present at every observation, since the API has no
    # expiry/window semantics to trigger a spontaneous removal.
    observations = 0
    deadline = time.monotonic() + 30.0
    while time.monotonic() < deadline:
        assert _is_present(ecr, principal_arn), (
            "exclusion disappeared from ListPullTimeUpdateExclusions before any "
            "deregistration was requested -- no TTL/expiry exists for this API"
        )
        observations += 1
        time.sleep(5.0)

    assert observations >= 3, "did not observe enough poll iterations to be meaningful"

    ecr.deregister_pull_time_update_exclusion(principalArn=principal_arn)
    assert not _is_present(ecr, principal_arn), "exclusion still present after explicit deregistration"

    try:
        ecr.deregister_pull_time_update_exclusion(principalArn=principal_arn)
    except ClientError as exc:
        assert exc.response["Error"]["Code"] == "ExclusionNotFoundException", (
            f"expected ExclusionNotFoundException on a re-deregister of a removed "
            f"exclusion, got {exc.response['Error']['Code']}"
        )
        message = exc.response["Error"].get("Message")
        expected_message = (
            f"The pull time update exclusion for principal arn '{principal_arn}' was not found "
            f"in registry with id '{account_id}'"
        )
        assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"
    else:
        raise AssertionError(
            "re-deregistering an already-removed exclusion succeeded instead of "
            "raising ExclusionNotFoundException"
        )


def _is_present(ecr, principal_arn: str) -> bool:
    token = None
    while True:
        kwargs = {"maxResults": 1000}
        if token:
            kwargs["nextToken"] = token
        resp = ecr.list_pull_time_update_exclusions(**kwargs)
        if principal_arn in resp.get("pullTimeUpdateExclusions", []):
            return True
        token = resp.get("nextToken")
        if not token:
            return False


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
