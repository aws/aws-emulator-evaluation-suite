"""pull-time-update-exclusion-fields-preserved."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "pull-time-update-exclusion-fields-preserved"
GROUP = "representation"
SERVICES = ["ecr"]

_TAGS = [{"Key": "sim2real:managed", "Value": "true"}]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:ecr-pull-time-exclusions")
def run(ctx) -> None:
    """The principalArn recorded by RegisterPullTimeUpdateExclusion is returned
    unchanged -- exact ARN string, no truncation or path-segment mangling -- by
    ListPullTimeUpdateExclusions."""
    ecr = ctx.client("ecr")
    iam = ctx.client("iam")

    role_name = ctx.unique_name("sim2real-ecr-ptu-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "ecr.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust_policy), Tags=_TAGS
    )
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    principal_arn = role["Role"]["Arn"]

    register_resp = ecr.register_pull_time_update_exclusion(principalArn=principal_arn)
    ctx.on_cleanup(lambda: ecr.deregister_pull_time_update_exclusion(principalArn=principal_arn))
    assert register_resp["principalArn"] == principal_arn, (
        f"expected principalArn {principal_arn!r} echoed unchanged, got "
        f"{register_resp['principalArn']!r}"
    )
    assert "createdAt" in register_resp, f"expected createdAt in response, got keys {list(register_resp)}"

    found_arn = _find_exclusion(ecr, principal_arn, timeout_s=30, interval_s=2)
    assert found_arn == principal_arn, (
        f"principalArn {principal_arn!r} from RegisterPullTimeUpdateExclusion did not appear "
        f"unchanged in ListPullTimeUpdateExclusions (last match: {found_arn!r})"
    )


def _find_exclusion(ecr, principal_arn: str, *, timeout_s: float, interval_s: float) -> str | None:
    deadline = time.monotonic() + timeout_s
    while True:
        next_token = None
        while True:
            kwargs = {"maxResults": 1000}
            if next_token:
                kwargs["nextToken"] = next_token
            resp = ecr.list_pull_time_update_exclusions(**kwargs)
            for arn in resp.get("pullTimeUpdateExclusions", []):
                if arn == principal_arn:
                    return arn
            next_token = resp.get("nextToken")
            if not next_token:
                break
        if time.monotonic() >= deadline:
            return None
        time.sleep(interval_s)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
