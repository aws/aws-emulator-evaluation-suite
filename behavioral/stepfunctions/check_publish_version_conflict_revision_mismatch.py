"""publish-version-conflict-revision-mismatch."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "publish-version-conflict-revision-mismatch"
GROUP = 'update_versioning'
SERVICES = ['stepfunctions']


def _create_sfn_role(ctx):
    """Create an execution role Step Functions may assume, deleted at cleanup."""
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-sfnrole-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "states.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    arn = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    return arn


def _call_once_role_assumable(create, **kwargs):
    """Call ``create``, retrying while a just-created role is not yet assumable."""
    deadline = time.monotonic() + 60.0
    while True:
        try:
            return create(**kwargs)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "AccessDeniedException" or time.monotonic() > deadline:
                raise
            time.sleep(3)


def _create_state_machine(ctx, definition, *, name=None, sm_type="STANDARD"):
    sfn = ctx.client("stepfunctions")
    name = name or ctx.unique_name("sim2real-behav-sm-")
    arn = _call_once_role_assumable(
        sfn.create_state_machine,
        name=name,
        definition=json.dumps(definition),
        roleArn=_create_sfn_role(ctx),
        type=sm_type,
        tags=[{"key": "sim2real-check", "value": CHECK}],
    )["stateMachineArn"]
    ctx.on_cleanup(lambda: sfn.delete_state_machine(stateMachineArn=arn))
    return arn


def _error_code(fn):
    try:
        fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError("expected a ClientError, call unexpectedly succeeded")


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _poll_until(fn, predicate, *, deadline_s, interval_s=2.0, reason, budget_s=None):
    start = time.monotonic()
    stop = start + (deadline_s if budget_s is None else min(deadline_s, budget_s))
    value = fn()
    while not predicate(value):
        if time.monotonic() >= stop:
            if budget_s is not None and budget_s < deadline_s:
                raise TimeoutError(
                    f"the check's time budget ran out after {time.monotonic() - start:.1f}s, before the "
                    f"{deadline_s}s wait for {reason} ended (last value: {value}); not graded"
                )
            raise AssertionError(f"timed out waiting for {reason}; last value: {value}")
        time.sleep(interval_s)
        value = fn()
    return value


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """PublishStateMachineVersion with a stale revisionId fails ConflictException with the exact
    message naming both revisions and creates no version, and the identical call with the current
    revisionId publishes; revisionId and version listings are read once they settle.
    """
    sfn = ctx.client("stepfunctions")
    def_v1 = {"StartAt": "Done", "States": {"Done": {"Type": "Pass", "Result": {"ok": True}, "End": True}}}
    def_v2 = {"StartAt": "Done2", "States": {"Done2": {"Type": "Pass", "Result": {"ok": 2}, "End": True}}}
    def_v3 = {"StartAt": "Done3", "States": {"Done3": {"Type": "Pass", "Result": {"ok": 3}, "End": True}}}
    arn = _create_state_machine(ctx, def_v1)

    # A freshly created state machine reports no revisionId at all; the field only appears
    # once the definition has changed at least once.
    # DescribeStateMachine may omit revisionId briefly after an update; poll until it appears.
    sfn.update_state_machine(stateMachineArn=arn, definition=json.dumps(def_v2))
    first_revision = _poll_until(
        lambda: sfn.describe_state_machine(stateMachineArn=arn).get("revisionId"),
        lambda rev: rev is not None,
        deadline_s=30.0,
        budget_s=_budget_s(ctx, 30.0),
        reason="DescribeStateMachine to report a revisionId",
    )

    # Positive control: publishing against the CURRENT revisionId succeeds.
    first_published = sfn.publish_state_machine_version(stateMachineArn=arn, revisionId=first_revision)
    first_version_arn = first_published["stateMachineVersionArn"]
    ctx.on_cleanup(lambda: sfn.delete_state_machine_version(stateMachineVersionArn=first_version_arn))

    versions_after_first_publish = _poll_until(
        lambda: sfn.list_state_machine_versions(stateMachineArn=arn)["stateMachineVersions"],
        lambda versions: len(versions) >= 1,
        deadline_s=30.0,
        budget_s=_budget_s(ctx, 30.0),
        reason="the first published version to appear in ListStateMachineVersions",
    )
    assert [v["stateMachineVersionArn"] for v in versions_after_first_publish] == [first_version_arn], (
        f"expected exactly the first published version listed, got {versions_after_first_publish}"
    )

    # Break: a concurrent UpdateStateMachine bumps the revisionId forward, making
    # first_revision stale.
    sfn.update_state_machine(stateMachineArn=arn, definition=json.dumps(def_v3))
    current_revision = _poll_until(
        lambda: sfn.describe_state_machine(stateMachineArn=arn).get("revisionId"),
        lambda rev: rev is not None and rev != first_revision,
        deadline_s=30.0,
        budget_s=_budget_s(ctx, 30.0),
        reason="DescribeStateMachine to report the updated revisionId",
    )
    assert current_revision != first_revision, (
        f"expected revisionId to change after UpdateStateMachine, both were {first_revision!r}"
    )

    code, message = _error_code(
        lambda: sfn.publish_state_machine_version(stateMachineArn=arn, revisionId=first_revision)
    )
    assert code == "ConflictException", f"expected ConflictException on stale revisionId, got {code}"
    expected_message = (
        f"Failed to publish the State Machine version for revision {first_revision}. "
        f"The current State Machine revision is {current_revision}."
    )
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    versions_after_conflict = sfn.list_state_machine_versions(stateMachineArn=arn)["stateMachineVersions"]
    assert [v["stateMachineVersionArn"] for v in versions_after_conflict] == [first_version_arn], (
        f"expected the rejected publish to create no new version, got {versions_after_conflict}"
    )

    # The identical call now succeeds once given the CURRENT revisionId.
    second_published = sfn.publish_state_machine_version(stateMachineArn=arn, revisionId=current_revision)
    second_version_arn = second_published["stateMachineVersionArn"]
    ctx.on_cleanup(lambda: sfn.delete_state_machine_version(stateMachineVersionArn=second_version_arn))

    # ListStateMachineVersions lags a just-completed publish by a few seconds; poll for it.
    versions_final = _poll_until(
        lambda: sfn.list_state_machine_versions(stateMachineArn=arn)["stateMachineVersions"],
        lambda versions: len(versions) >= 2,
        deadline_s=30.0,
        budget_s=_budget_s(ctx, 30.0),
        reason="the second published version to appear in ListStateMachineVersions",
    )
    assert sorted(v["stateMachineVersionArn"] for v in versions_final) == sorted(
        [first_version_arn, second_version_arn]
    ), f"expected both published versions listed, got {versions_final}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
