"""pull-time-update-exclusion-lifecycle."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "pull-time-update-exclusion-lifecycle"
GROUP = "state-machine"
SERVICES = ["ecr"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:ecr-pull-time-exclusions")
def run(ctx) -> None:
    """A registered pull-time-update exclusion shows up in ListPullTimeUpdateExclusions,
    and DeregisterPullTimeUpdateExclusion removes it from a subsequent list call."""
    ecr = ctx.client("ecr")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    role_name = ctx.unique_name("sim2real-ecr-exclusion-role")
    principal_arn = f"arn:aws:iam::{account_id}:role/{role_name}"

    ecr.register_pull_time_update_exclusion(principalArn=principal_arn)
    ctx.on_cleanup(lambda: _deregister_or_ignore(ecr, principal_arn))

    present = _poll_until(
        lambda: principal_arn in _list_all_principal_arns(ecr),
        lambda found: found is True,
        timeout_s=30,
        interval_s=2,
    )
    assert present is True, (
        f"expected {principal_arn} to appear in ListPullTimeUpdateExclusions after "
        f"RegisterPullTimeUpdateExclusion, got present={present!r}"
    )

    ecr.deregister_pull_time_update_exclusion(principalArn=principal_arn)

    absent = _poll_until(
        lambda: principal_arn in _list_all_principal_arns(ecr),
        lambda found: found is False,
        timeout_s=30,
        interval_s=2,
    )
    assert absent is False, (
        f"expected {principal_arn} to be gone from ListPullTimeUpdateExclusions after "
        f"DeregisterPullTimeUpdateExclusion, got present={absent!r}"
    )


def _list_all_principal_arns(ecr) -> list[str]:
    arns: list[str] = []
    next_token = None
    while True:
        kwargs = {"maxResults": 1000}
        if next_token:
            kwargs["nextToken"] = next_token
        resp = ecr.list_pull_time_update_exclusions(**kwargs)
        for e in resp.get("pullTimeUpdateExclusions", []):
            if isinstance(e, dict):
                arn = e.get("principalArn") or e.get("PrincipalArn")
            else:
                arn = e
            if arn:
                arns.append(arn)
        next_token = resp.get("nextToken")
        if not next_token:
            break
    return arns


def _deregister_or_ignore(ecr, principal_arn: str) -> None:
    from botocore.exceptions import ClientError

    try:
        ecr.deregister_pull_time_update_exclusion(principalArn=principal_arn)
    except ClientError as err:
        if err.response["Error"]["Code"] != "ExclusionNotFoundException":
            raise


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float):
    deadline = time.monotonic() + timeout_s
    value = probe()
    while not predicate(value):
        if time.monotonic() >= deadline:
            raise AssertionError(f"condition never satisfied within {timeout_s}s (last={value!r})")
        time.sleep(interval_s)
        value = probe()
    return value


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
