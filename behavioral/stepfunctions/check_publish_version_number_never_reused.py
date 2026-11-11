"""publish-version-number-never-reused."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "publish-version-number-never-reused"
GROUP = "update_versioning"
SERVICES = ["stepfunctions"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Deleting a published version and re-publishing the same, unchanged revision assigns
    the next version number rather than reusing the deleted one.
    """
    sfn = ctx.client("stepfunctions")
    role_arn = _create_sfn_role(ctx)
    sm_arn = _create_state_machine(ctx, sfn, role_arn)

    first = sfn.publish_state_machine_version(stateMachineArn=sm_arn)
    first_arn = first["stateMachineVersionArn"]
    assert first_arn == f"{sm_arn}:1", f"expected the first published version to be ':1', got {first_arn!r}"

    sfn.delete_state_machine_version(stateMachineVersionArn=first_arn)

    # DeleteStateMachineVersion is asynchronous: poll until the version is gone before
    # re-publishing, so the second publish is not racing the first version's own deletion.
    _poll_until(
        lambda: set(_list_versions(sfn, sm_arn)),
        lambda vs: first_arn not in vs,
        timeout_s=60.0,
        interval_s=2.0,
    )

    second = sfn.publish_state_machine_version(stateMachineArn=sm_arn)
    second_arn = second["stateMachineVersionArn"]
    ctx.on_cleanup(lambda: _swallow_not_found(lambda: sfn.delete_state_machine_version(stateMachineVersionArn=second_arn)))
    assert second_arn == f"{sm_arn}:2", (
        f"expected the version number after a deleted ':1' to advance to ':2', never reusing "
        f"the deleted number, got {second_arn!r}"
    )

    # ListStateMachineVersions lags a just-completed publish by a few seconds; poll for it.
    versions_after = _poll_until(
        lambda: set(_list_versions(sfn, sm_arn)),
        lambda vs: second_arn in vs,
        timeout_s=60.0,
        interval_s=2.0,
    )
    assert first_arn not in versions_after, f"deleted version reappeared: {versions_after!r}"

    described = sfn.describe_state_machine(stateMachineArn=second_arn)
    assert described["stateMachineArn"] == second_arn, (
        f"the re-published version must be independently describable by its own ARN, got {described!r}"
    )


def _list_versions(sfn, sm_arn):
    out = []
    next_token = None
    while True:
        kwargs = {"stateMachineArn": sm_arn}
        if next_token:
            kwargs["nextToken"] = next_token
        page = sfn.list_state_machine_versions(**kwargs)
        out.extend(v["stateMachineVersionArn"] for v in page["stateMachineVersions"])
        next_token = page.get("nextToken")
        if not next_token:
            break
    return out


def _poll_until(probe, predicate, *, timeout_s, interval_s):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


_SFN_TRUST_POLICY = json.dumps(
    {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "states.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
)

_PASS_DEFINITION = json.dumps(
    {"Comment": "behavioral-pass", "StartAt": "P", "States": {"P": {"Type": "Pass", "End": True}}}
)


def _swallow_not_found(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchEntity", "StateMachineDoesNotExist"):
            raise


def _create_sfn_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-sfnrole-")
    role_arn = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=_SFN_TRUST_POLICY
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: _swallow_not_found(lambda: iam.delete_role(RoleName=role_name)))
    return role_arn


def _create_state_machine(ctx, sfn, role_arn: str) -> str:
    """CreateStateMachine, retrying AccessDeniedException while the freshly created
    role's trust policy propagates."""
    name = ctx.unique_name("sim2real-behav-sfn-")
    deadline = time.monotonic() + 90.0
    last_err = None
    resp = None
    while time.monotonic() < deadline:
        try:
            resp = sfn.create_state_machine(name=name, definition=_PASS_DEFINITION, roleArn=role_arn)
            break
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "AccessDeniedException":
                last_err = exc
                time.sleep(5)
                continue
            raise
    if resp is None:
        raise AssertionError(
            f"could not create state machine after role propagation wait: {last_err}"
        )
    arn = resp["stateMachineArn"]
    ctx.on_cleanup(lambda: _swallow_not_found(lambda: sfn.delete_state_machine(stateMachineArn=arn)))
    return arn


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
