"""error-conflict-publish-version-stale-revision."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "error-conflict-publish-version-stale-revision"
GROUP = "error-semantics"
SERVICES = ["stepfunctions"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """PublishStateMachineVersion with a stale revisionId is rejected with ConflictException and
    creates no version; publishing with the current revisionId then adds exactly one version."""
    sfn = ctx.client("stepfunctions")
    role_arn = _create_sfn_role(ctx)

    name = ctx.unique_name("sim2real-behav-sm-pub-")
    def_v0 = json.dumps({"StartAt": "Pass0", "States": {"Pass0": {"Type": "Pass", "End": True}}})
    def_v1 = json.dumps({"StartAt": "Pass1", "States": {"Pass1": {"Type": "Pass", "End": True}}})
    def_v2 = json.dumps({"StartAt": "Pass2", "States": {"Pass2": {"Type": "Pass", "End": True}}})

    sm_arn = _create_state_machine(ctx, sfn, name, def_v0, role_arn)

    # A new state machine has no revisionId; only a real definition change populates it, and
    # asynchronously, so the stale revisionId comes from a prior update.
    sfn.update_state_machine(stateMachineArn=sm_arn, definition=def_v1)
    stale_revision = _wait_for_revision_id(sfn, sm_arn)

    versions_before = len(sfn.list_state_machine_versions(stateMachineArn=sm_arn)["stateMachineVersions"])

    # Concurrent update bumps the revisionId forward again.
    sfn.update_state_machine(stateMachineArn=sm_arn, definition=def_v2)
    current_revision = _wait_for_revision_id(sfn, sm_arn, differs_from=stale_revision)
    assert current_revision != stale_revision, "revisionId did not change after the second UpdateStateMachine"

    code, message = _refusal(
        lambda: sfn.publish_state_machine_version(stateMachineArn=sm_arn, revisionId=stale_revision)
    )
    assert code == "ConflictException", f"expected ConflictException, got {code!r}"
    expected_message = (
        f"Failed to publish the State Machine version for revision {stale_revision}. "
        f"The current State Machine revision is {current_revision}."
    )
    assert message == expected_message, (
        f"expected message {expected_message!r}, got {message!r}"
    )

    versions_after_reject = sfn.list_state_machine_versions(stateMachineArn=sm_arn)["stateMachineVersions"]
    assert len(versions_after_reject) == versions_before, (
        f"stale-revision publish was rejected but a version appeared anyway: "
        f"{versions_before} -> {len(versions_after_reject)}: {versions_after_reject!r}"
    )

    published = sfn.publish_state_machine_version(stateMachineArn=sm_arn, revisionId=current_revision)
    version_arn = published["stateMachineVersionArn"]
    ctx.on_cleanup(lambda: sfn.delete_state_machine_version(stateMachineVersionArn=version_arn))

    versions_final = _poll_until(
        lambda: sfn.list_state_machine_versions(stateMachineArn=sm_arn)["stateMachineVersions"],
        lambda vs: any(v["stateMachineVersionArn"] == version_arn for v in vs),
        timeout=30.0,
    )
    assert len(versions_final) == versions_before + 1, (
        f"expected exactly one new version after the accepted publish: "
        f"{versions_before} -> {len(versions_final)}: {versions_final!r}"
    )


def _refusal(fn):
    """Call fn(); return the (code, message) it is refused with, raising if it succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be refused, it succeeded with {result!r}")


def _wait_for_revision_id(sfn, sm_arn, *, differs_from=None, timeout=30.0, interval=2.0):
    """Poll for revisionId, which DescribeStateMachine may briefly omit or report stale after an
    UpdateStateMachine that changed the definition."""
    deadline = time.monotonic() + timeout
    last = None
    while True:
        last = sfn.describe_state_machine(stateMachineArn=sm_arn).get("revisionId")
        if last is not None and (differs_from is None or last != differs_from):
            return last
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"revisionId on {sm_arn} did not settle to a new value within {timeout}s: "
                f"last saw {last!r}, waiting to differ from {differs_from!r}"
            )
        time.sleep(interval)


def _poll_until(probe, predicate, *, timeout, interval=2.0):
    deadline = time.monotonic() + timeout
    last = None
    while True:
        last = probe()
        if predicate(last):
            return last
        if time.monotonic() >= deadline:
            raise AssertionError(f"condition not observed within {timeout}s; last saw {last!r}")
        time.sleep(interval)


def _create_sfn_role(ctx, inline_statements=None):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-sfn-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "states.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    }
    resp = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))
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


def _create_state_machine(ctx, sfn, name, definition, role_arn):
    """CreateStateMachine, retrying AccessDeniedException while the new role propagates in IAM."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + 90.0
    last_err = None
    resp = None
    while time.monotonic() < deadline:
        try:
            resp = sfn.create_state_machine(name=name, definition=definition, roleArn=role_arn)
            break
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "AccessDeniedException":
                last_err = exc
                time.sleep(5)
                continue
            raise
    if resp is None:
        raise AssertionError(f"could not create state machine after role propagation wait: {last_err}")
    sm_arn = resp["stateMachineArn"]
    ctx.on_cleanup(lambda: sfn.delete_state_machine(stateMachineArn=sm_arn))
    return sm_arn


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
