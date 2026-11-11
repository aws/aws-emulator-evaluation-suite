"""request-tag-and-tag-keys-conditions-deny-forbidden-tag-mutations."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "request-tag-and-tag-keys-conditions-deny-forbidden-tag-mutations"
GROUP = "enforcement"
SERVICES = ["stepfunctions"]

_SESSION_NAME = "sim2real-behav-reqtag-session"
_FORBIDDEN_KEY = "sim2real-forbidden"
_FORBIDDEN_VALUE = "blocked"


@tags("axis:rejection", "cap:c7", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """An identity policy denying CreateStateMachine/CreateActivity/TagResource under an
    aws:RequestTag/K=V condition, and UntagResource under a ForAnyValue:aws:TagKeys condition,
    refuses exactly the forbidden tag or key on each action while a non-forbidden one passes.
    """
    sfn = ctx.client("stepfunctions")
    sts = ctx.client("sts")
    iam = ctx.client("iam")

    exec_role_arn = _create_sfn_exec_role(ctx, iam)
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": [
                    "states:CreateStateMachine",
                    "states:CreateActivity",
                    "states:DeleteStateMachine",
                    "states:DeleteActivity",
                    "states:TagResource",
                    "states:UntagResource",
                    "iam:PassRole",
                ],
                "Resource": "*",
            },
            {
                "Effect": "Deny",
                "Action": [
                    "states:CreateStateMachine",
                    "states:CreateActivity",
                    "states:TagResource",
                ],
                "Resource": "*",
                "Condition": {
                    "StringEquals": {f"aws:RequestTag/{_FORBIDDEN_KEY}": _FORBIDDEN_VALUE}
                },
            },
            {
                "Effect": "Deny",
                "Action": "states:UntagResource",
                "Resource": "*",
                "Condition": {
                    "ForAnyValue:StringEquals": {"aws:TagKeys": [_FORBIDDEN_KEY]}
                },
            },
        ],
    }
    role_arn, role_name = _create_role(ctx, iam, policy)
    as_role = _client_as(ctx, _assume(sts, role_arn))
    session_arn = f"arn:aws:sts::{ctx.account}:assumed-role/{role_name}/{_SESSION_NAME}"

    definition = json.dumps({"StartAt": "Done", "States": {"Done": {"Type": "Pass", "End": True}}})

    # Positive control first: once a tagged create the policy permits succeeds, the policy has
    # propagated, so every refusal that follows below is an evaluation of the condition.
    ok_name = ctx.unique_name("sim2real-behav-reqtag-sm-")
    ok_arn = _poll_create(
        lambda: as_role.create_state_machine(
            name=ok_name, definition=definition, roleArn=exec_role_arn, type="STANDARD",
            tags=[{"key": "sim2real-other", "value": "allowed"}],
        )["stateMachineArn"],
        timeout_s=240.0,
    )
    ctx.on_cleanup(_teardown(lambda: sfn.delete_state_machine(stateMachineArn=ok_arn)))

    def denied(action: str, resource_arn: str) -> tuple[str, str]:
        return (
            "AccessDeniedException",
            f"User: {session_arn} is not authorized to perform: {action} on resource: "
            f"{resource_arn} with an explicit deny in an identity-based policy",
        )

    # 1. CreateStateMachine carrying the forbidden tag is refused by its own action name.
    bad_sm_name = ctx.unique_name("sim2real-behav-reqtag-sm-")
    bad_sm_arn = f"arn:aws:states:{ctx.region}:{ctx.account}:stateMachine:{bad_sm_name}"
    code, message = _refusal(
        ctx, sfn,
        lambda: as_role.create_state_machine(
            name=bad_sm_name, definition=definition, roleArn=exec_role_arn, type="STANDARD",
            tags=[{"key": _FORBIDDEN_KEY, "value": _FORBIDDEN_VALUE}],
        ),
        extract_arn=lambda r: r["stateMachineArn"],
        delete=lambda arn: sfn.delete_state_machine(stateMachineArn=arn),
    )
    assert (code, message) == denied("states:CreateStateMachine", bad_sm_arn), (
        f"forbidden-tagged CreateStateMachine: expected {denied('states:CreateStateMachine', bad_sm_arn)!r}, "
        f"got {(code, message)!r}"
    )
    describe_code = _error_code(lambda: sfn.describe_state_machine(stateMachineArn=bad_sm_arn))
    assert describe_code == "StateMachineDoesNotExist", (
        f"a refused CreateStateMachine must leave no state machine; DescribeStateMachine gave {describe_code!r}"
    )

    # 2. CreateActivity carrying the forbidden tag is refused by its own action name.
    bad_act_name = ctx.unique_name("sim2real-behav-reqtag-act-")
    bad_act_arn = f"arn:aws:states:{ctx.region}:{ctx.account}:activity:{bad_act_name}"
    code, message = _refusal(
        ctx, sfn,
        lambda: as_role.create_activity(
            name=bad_act_name, tags=[{"key": _FORBIDDEN_KEY, "value": _FORBIDDEN_VALUE}],
        ),
        extract_arn=lambda r: r["activityArn"],
        delete=lambda arn: sfn.delete_activity(activityArn=arn),
    )
    assert (code, message) == denied("states:CreateActivity", bad_act_arn), (
        f"forbidden-tagged CreateActivity: expected {denied('states:CreateActivity', bad_act_arn)!r}, "
        f"got {(code, message)!r}"
    )
    describe_code = _error_code(lambda: sfn.describe_activity(activityArn=bad_act_arn))
    assert describe_code == "ActivityDoesNotExist", (
        f"a refused CreateActivity must leave no activity; DescribeActivity gave {describe_code!r}"
    )

    # 3. TagResource adding the forbidden key/value onto an existing (allowed) resource is refused.
    code, message = _error_code_and_message(
        lambda: as_role.tag_resource(
            resourceArn=ok_arn, tags=[{"key": _FORBIDDEN_KEY, "value": _FORBIDDEN_VALUE}],
        )
    )
    assert (code, message) == denied("states:TagResource", ok_arn), (
        f"forbidden TagResource: expected {denied('states:TagResource', ok_arn)!r}, got {(code, message)!r}"
    )
    held = {t["key"]: t["value"] for t in sfn.list_tags_for_resource(resourceArn=ok_arn)["tags"]}
    assert _FORBIDDEN_KEY not in held, f"a refused TagResource must not add the tag; held tags are {held!r}"

    # 4. A non-forbidden TagResource on the same resource still succeeds.
    as_role.tag_resource(resourceArn=ok_arn, tags=[{"key": "sim2real-second", "value": "ok"}])
    held = {t["key"]: t["value"] for t in sfn.list_tags_for_resource(resourceArn=ok_arn)["tags"]}
    assert held.get("sim2real-second") == "ok", f"the non-forbidden tag was not stored; held tags are {held!r}"

    # 5. UntagResource naming the forbidden key is refused, whether or not that key is present.
    code, message = _error_code_and_message(
        lambda: as_role.untag_resource(resourceArn=ok_arn, tagKeys=[_FORBIDDEN_KEY])
    )
    assert (code, message) == denied("states:UntagResource", ok_arn), (
        f"forbidden UntagResource: expected {denied('states:UntagResource', ok_arn)!r}, got {(code, message)!r}"
    )

    # 6. UntagResource naming only a non-forbidden key still succeeds.
    as_role.untag_resource(resourceArn=ok_arn, tagKeys=["sim2real-second"])
    held = {t["key"]: t["value"] for t in sfn.list_tags_for_resource(resourceArn=ok_arn)["tags"]}
    assert "sim2real-second" not in held, f"the non-forbidden key was not removed; held tags are {held!r}"
    assert held.get("sim2real-other") == "allowed", (
        f"an unrelated tag must survive an unrelated UntagResource; held tags are {held!r}"
    )


def _create_sfn_exec_role(ctx, iam) -> str:
    role_name = ctx.unique_name("sim2real-behav-reqtag-execrole-")
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
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(_teardown(lambda: iam.delete_role(RoleName=role_name), "NoSuchEntity"))
    return role["Role"]["Arn"]


def _create_role(ctx, iam, policy) -> tuple[str, str]:
    role_name = ctx.unique_name("sim2real-behav-reqtag-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{ctx.account}:root"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(_teardown(lambda: iam.delete_role(RoleName=role_name), "NoSuchEntity"))
    iam.put_role_policy(RoleName=role_name, PolicyName="restricted", PolicyDocument=json.dumps(policy))
    ctx.on_cleanup(
        _teardown(
            lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="restricted"),
            "NoSuchEntity",
        )
    )
    return role["Role"]["Arn"], role_name


def _assume(sts, role_arn: str, timeout_s: float = 150.0, interval_s: float = 2.0) -> dict:
    """Assume the freshly created role, retrying while its trust policy propagates."""
    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            return sts.assume_role(RoleArn=role_arn, RoleSessionName=_SESSION_NAME)["Credentials"]
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "AccessDenied":
                raise
            last_err = exc
            time.sleep(interval_s)
    raise AssertionError(f"assume-role never succeeded (trust policy propagation?): {last_err}")


def _client_as(ctx, creds: dict):
    return ctx.client(
        "stepfunctions",
        creds={
            "aws_access_key_id": creds["AccessKeyId"],
            "aws_secret_access_key": creds["SecretAccessKey"],
            "aws_session_token": creds["SessionToken"],
        },
    )


def _poll_create(fn, *, timeout_s: float, interval_s: float = 2.0) -> str:
    """The first create the role's policy permits, retried only while IAM propagates."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return fn()
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code not in ("AccessDeniedException", "UnrecognizedClientException", "InvalidClientTokenId") or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)


def _refusal(ctx, sfn, fn, *, extract_arn, delete):
    """(code, message) of the refused call; an unexpected success registers its delete first."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), error.get("Message", "")
    arn = extract_arn(result)
    ctx.on_cleanup(_teardown(lambda: delete(arn)))
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _error_code(fn) -> str:
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"]
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _error_code_and_message(fn) -> tuple[str, str]:
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), error.get("Message", "")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _teardown(undo, *not_found: str):
    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
