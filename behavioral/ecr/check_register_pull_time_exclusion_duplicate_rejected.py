"""register-pull-time-exclusion-duplicate-rejected."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "register-pull-time-exclusion-duplicate-rejected"
GROUP = "overly-permissive"
SERVICES = ["ecr"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control", "resource:account-singleton:ecr-pull-time-exclusions")
def run(ctx) -> None:
    """Registering the same pull-time-update exclusion principal twice raises
    ExclusionAlreadyExistsException instead of silently succeeding a second time,
    while a distinct principal (positive control) registers cleanly."""
    ecr = ctx.client("ecr")
    iam = ctx.client("iam")

    role_a_arn = _create_iam_role(ctx, iam, "excl-a")
    role_b_arn = _create_iam_role(ctx, iam, "excl-b")

    ecr.register_pull_time_update_exclusion(principalArn=role_a_arn)
    ctx.on_cleanup(lambda: _deregister(ecr, role_a_arn))

    code, message = _client_error(lambda: ecr.register_pull_time_update_exclusion(principalArn=role_a_arn))
    assert code == "ExclusionAlreadyExistsException", f"expected ExclusionAlreadyExistsException, got {code}"
    expected = (
        f"The pull time update exclusion for principal arn '{role_a_arn}' already exists in "
        f"registry with id '{role_a_arn.split(':')[4]}'"
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    exclusions = _list_all_exclusions(ecr)
    matches_a = [e for e in exclusions if e == role_a_arn]
    assert len(matches_a) == 1, f"expected exactly one exclusion entry for {role_a_arn}, got {len(matches_a)}"

    # restore: the block is tied to the duplicate registration, not to role_a itself —
    # deregistering must make the identifier reusable, and the identical call must then succeed
    ecr.deregister_pull_time_update_exclusion(principalArn=role_a_arn)
    assert role_a_arn not in _list_all_exclusions(ecr), f"{role_a_arn} still listed after deregister"

    ecr.register_pull_time_update_exclusion(principalArn=role_a_arn)
    assert role_a_arn in _list_all_exclusions(ecr), f"{role_a_arn} missing after re-registration"

    # positive control: a distinct principal still registers successfully
    ecr.register_pull_time_update_exclusion(principalArn=role_b_arn)
    ctx.on_cleanup(lambda: _deregister(ecr, role_b_arn))
    exclusions_after = _list_all_exclusions(ecr)
    assert role_b_arn in exclusions_after, f"{role_b_arn} missing from exclusions after registration"


def _client_error(fn):
    """Call fn(); return the (code, message) of the ClientError it raises. An unexpected success
    raises, so an emulator that accepts what AWS refuses fails loudly instead of reading as a
    code mismatch."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _deregister(ecr, principal_arn: str) -> None:
    try:
        ecr.deregister_pull_time_update_exclusion(principalArn=principal_arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ExclusionNotFoundException":
            raise


def _create_iam_role(ctx, iam, suffix: str) -> str:
    role_name = ctx.unique_name(f"sim2real-ecr-{suffix}-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "ec2.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }],
    }
    resp = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    arn = resp["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    return arn


def _list_all_exclusions(ecr):
    out = []
    token = None
    while True:
        kwargs = {"maxResults": 1000}
        if token:
            kwargs["nextToken"] = token
        resp = ecr.list_pull_time_update_exclusions(**kwargs)
        out.extend(resp.get("pullTimeUpdateExclusions", []))
        token = resp.get("nextToken")
        if not token:
            break
    return out


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
