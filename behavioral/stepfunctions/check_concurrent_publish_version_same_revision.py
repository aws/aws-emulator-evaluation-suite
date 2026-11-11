"""concurrent-publish-version-same-revision."""
from __future__ import annotations

import json
import threading
import time
from concurrent.futures import ThreadPoolExecutor

from behavioral_harness import tags

CHECK = "concurrent-publish-version-same-revision"
GROUP = "concurrency"
SERVICES = ["stepfunctions"]

_RACERS = 5


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Concurrent PublishStateMachineVersion calls pinned to one revisionId converge on exactly one
    new version: every racer resolves to the same version ARN, with no duplicate versions."""
    sfn = ctx.client("stepfunctions")
    role_arn = _create_sfn_role(ctx)

    def0 = json.dumps({"StartAt": "Pass", "States": {"Pass": {"Type": "Pass", "End": True}}})
    sm_name = ctx.unique_name("sim2real-behav-sm-pubrace-")
    sm_arn = _create_state_machine_with_role_wait(sfn, sm_name, def0, role_arn)
    ctx.on_cleanup(lambda: sfn.delete_state_machine(stateMachineArn=sm_arn))

    # A new state machine has no revisionId, and neither publishing nor a no-op update assigns
    # one; only an UpdateStateMachine with a changed definition does.
    def1 = json.dumps({"StartAt": "Pass", "States": {"Pass": {"Type": "Pass", "Comment": "seed-revision", "End": True}}})
    sfn.update_state_machine(stateMachineArn=sm_arn, definition=def1, roleArn=role_arn)

    base_rev = _wait_for_revision_id(sfn, sm_arn)

    versions_before = len(sfn.list_state_machine_versions(stateMachineArn=sm_arn)["stateMachineVersions"])

    barrier = threading.Barrier(_RACERS)

    def _publish():
        # Truly concurrent publishes on one revision fail ConflictException; retries converge.
        from botocore.exceptions import ClientError

        barrier.wait(timeout=10)
        deadline = time.time() + 30.0
        attempt = 0
        while True:
            try:
                return sfn.publish_state_machine_version(stateMachineArn=sm_arn, revisionId=base_rev)
            except ClientError as e:
                if e.response.get("Error", {}).get("Code") != "ConflictException" or time.time() >= deadline:
                    raise
                attempt += 1
                time.sleep(min(0.25 * attempt, 2.0))

    with ThreadPoolExecutor(max_workers=_RACERS) as pool:
        futures = [pool.submit(_publish) for _ in range(_RACERS)]
        results = [f.result() for f in futures]

    version_arns = {r["stateMachineVersionArn"] for r in results}
    assert len(version_arns) == 1, f"expected all {_RACERS} racers to converge on one version ARN, got {version_arns!r}"
    version_arn = version_arns.pop()
    ctx.on_cleanup(lambda: _delete_version_quiet(sfn, version_arn))

    # ListStateMachineVersions is eventually consistent and may briefly omit the new version.
    deadline = time.time() + 30.0
    versions_after = []
    while True:
        versions_after = sfn.list_state_machine_versions(stateMachineArn=sm_arn)["stateMachineVersions"]
        if any(v["stateMachineVersionArn"] == version_arn for v in versions_after):
            break
        if time.time() >= deadline:
            break
        time.sleep(2.0)

    assert len(versions_after) == versions_before + 1, (
        f"expected exactly one new version to be created by {_RACERS} concurrent idempotent publishes, "
        f"went from {versions_before} to {len(versions_after)}: {versions_after!r}"
    )
    assert any(v["stateMachineVersionArn"] == version_arn for v in versions_after), (
        f"expected the converged version {version_arn!r} to appear in list_state_machine_versions, "
        f"got {[v['stateMachineVersionArn'] for v in versions_after]!r}"
    )


def _wait_for_revision_id(sfn, sm_arn: str, timeout: float = 30.0, interval: float = 2.0) -> str:
    """Poll DescribeStateMachine for revisionId, which may briefly be absent after an update."""
    deadline = time.time() + timeout
    while True:
        desc = sfn.describe_state_machine(stateMachineArn=sm_arn)
        if "revisionId" in desc:
            return desc["revisionId"]
        if time.time() >= deadline:
            raise AssertionError(
                f"revisionId never appeared on {sm_arn} within {timeout}s after publishing a version"
            )
        time.sleep(interval)


def _delete_version_quiet(sfn, version_arn: str) -> None:
    from botocore.exceptions import ClientError

    sfn.delete_state_machine_version(stateMachineVersionArn=version_arn)


def _create_sfn_role(ctx, inline_statements=None):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-sfn-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "states.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    resp = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": "audit-concurrent-publish-version-same-revision"}],
    )
    role_arn = resp["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    if inline_statements:
        policy_name = ctx.unique_name("sim2real-sfn-policy-")
        iam.put_role_policy(
            RoleName=role_name,
            PolicyName=policy_name,
            PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": inline_statements}),
        )
        ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))
    return role_arn


def _create_state_machine_with_role_wait(sfn, name: str, definition: str, role_arn: str, timeout: float = 90.0) -> str:
    """CreateStateMachine, retrying AccessDeniedException while a new role's trust propagates."""
    from botocore.exceptions import ClientError

    deadline = time.time() + timeout
    last_err = None
    while time.time() < deadline:
        try:
            return sfn.create_state_machine(
                name=name,
                definition=definition,
                roleArn=role_arn,
                tags=[{"key": "sim2real", "value": "audit-concurrent-publish-version-same-revision"}],
            )["stateMachineArn"]
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "AccessDeniedException":
                raise
            last_err = exc
            time.sleep(3)
    raise AssertionError(f"create_state_machine did not succeed within {timeout}s of role creation: {last_err}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
