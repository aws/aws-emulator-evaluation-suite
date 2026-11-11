"""create-with-tags-implicitly-requires-tagresource-permission."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-with-tags-implicitly-requires-tagresource-permission"
GROUP = "enforcement"
SERVICES = ["stepfunctions"]

_SESSION_NAME = "sim2real-behav-createtag-session"
_FORBIDDEN_KEY = "sim2real-forbidden"
_FORBIDDEN_VALUE = "blocked"


@tags("axis:rejection", "cap:c7", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateStateMachine/CreateActivity with a `tags` parameter also authorizes
    states:TagResource: a Deny on TagResource, conditioned on aws:RequestTag/K=V or
    aws:ResourceTag/K=V, rejects a tagged create naming states:TagResource, not the create.
    """
    sfn = ctx.client("stepfunctions")
    sts = ctx.client("sts")
    iam = ctx.client("iam")

    exec_role_arn = _create_sfn_exec_role(ctx, iam)
    definition = json.dumps({"StartAt": "Done", "States": {"Done": {"Type": "Pass", "End": True}}})

    def denied(resource_arn: str, session_arn: str) -> tuple[str, str]:
        return (
            "AccessDeniedException",
            f"User: {session_arn} is not authorized to perform: states:TagResource on resource: "
            f"{resource_arn} with an explicit deny in an identity-based policy",
        )

    # --- Variant 1: the Deny on TagResource is conditioned on aws:RequestTag/K=V. ---
    policy_request_tag = _tagresource_deny_policy({"StringEquals": {f"aws:RequestTag/{_FORBIDDEN_KEY}": _FORBIDDEN_VALUE}})
    role_arn_a, role_name_a = _create_role(ctx, iam, policy_request_tag, "a")
    as_role_a = _client_as(ctx, _assume(sts, role_arn_a))
    session_arn_a = f"arn:aws:sts::{ctx.account}:assumed-role/{role_name_a}/{_SESSION_NAME}"

    ok_name = ctx.unique_name("sim2real-behav-createtag-sm-")
    ok_arn = _poll_create(
        lambda: as_role_a.create_state_machine(
            name=ok_name, definition=definition, roleArn=exec_role_arn, type="STANDARD",
            tags=[{"key": "sim2real-other", "value": "allowed"}],
        )["stateMachineArn"],
        timeout_s=240.0,
    )
    ctx.on_cleanup(_teardown(lambda: sfn.delete_state_machine(stateMachineArn=ok_arn)))

    bad_sm_name = ctx.unique_name("sim2real-behav-createtag-sm-")
    bad_sm_arn = f"arn:aws:states:{ctx.region}:{ctx.account}:stateMachine:{bad_sm_name}"
    code, message = _refusal(
        ctx,
        lambda: as_role_a.create_state_machine(
            name=bad_sm_name, definition=definition, roleArn=exec_role_arn, type="STANDARD",
            tags=[{"key": _FORBIDDEN_KEY, "value": _FORBIDDEN_VALUE}],
        ),
        extract_arn=lambda r: r["stateMachineArn"],
        delete=lambda arn: sfn.delete_state_machine(stateMachineArn=arn),
    )
    assert (code, message) == denied(bad_sm_arn, session_arn_a), (
        f"RequestTag-denied CreateStateMachine: expected {denied(bad_sm_arn, session_arn_a)!r}, "
        f"got {(code, message)!r}"
    )
    describe_code = _error_code(lambda: sfn.describe_state_machine(stateMachineArn=bad_sm_arn))
    assert describe_code == "StateMachineDoesNotExist", (
        f"a TagResource-refused CreateStateMachine must leave no state machine; got {describe_code!r}"
    )

    bad_act_name = ctx.unique_name("sim2real-behav-createtag-act-")
    bad_act_arn = f"arn:aws:states:{ctx.region}:{ctx.account}:activity:{bad_act_name}"
    code, message = _refusal(
        ctx,
        lambda: as_role_a.create_activity(
            name=bad_act_name, tags=[{"key": _FORBIDDEN_KEY, "value": _FORBIDDEN_VALUE}],
        ),
        extract_arn=lambda r: r["activityArn"],
        delete=lambda arn: sfn.delete_activity(activityArn=arn),
    )
    assert (code, message) == denied(bad_act_arn, session_arn_a), (
        f"RequestTag-denied CreateActivity: expected {denied(bad_act_arn, session_arn_a)!r}, "
        f"got {(code, message)!r}"
    )
    describe_code = _error_code(lambda: sfn.describe_activity(activityArn=bad_act_arn))
    assert describe_code == "ActivityDoesNotExist", (
        f"a TagResource-refused CreateActivity must leave no activity; got {describe_code!r}"
    )

    # --- Variant 2: the Deny on TagResource is conditioned on aws:ResourceTag/K=V -- evaluated,
    # for a Create call, against the tags carried on the very request that is creating the
    # resource (there being no pre-existing resource to read tags from). ---
    policy_resource_tag = _tagresource_deny_policy({"StringEquals": {f"aws:ResourceTag/{_FORBIDDEN_KEY}": _FORBIDDEN_VALUE}})
    role_arn_b, role_name_b = _create_role(ctx, iam, policy_resource_tag, "b")
    as_role_b = _client_as(ctx, _assume(sts, role_arn_b))
    session_arn_b = f"arn:aws:sts::{ctx.account}:assumed-role/{role_name_b}/{_SESSION_NAME}"

    ok_name_b = ctx.unique_name("sim2real-behav-createtag-sm-")
    ok_arn_b = _poll_create(
        lambda: as_role_b.create_state_machine(
            name=ok_name_b, definition=definition, roleArn=exec_role_arn, type="STANDARD",
            tags=[{"key": "sim2real-other", "value": "allowed"}],
        )["stateMachineArn"],
        timeout_s=240.0,
    )
    ctx.on_cleanup(_teardown(lambda: sfn.delete_state_machine(stateMachineArn=ok_arn_b)))

    bad_sm_name_b = ctx.unique_name("sim2real-behav-createtag-sm-")
    bad_sm_arn_b = f"arn:aws:states:{ctx.region}:{ctx.account}:stateMachine:{bad_sm_name_b}"
    code, message = _refusal(
        ctx,
        lambda: as_role_b.create_state_machine(
            name=bad_sm_name_b, definition=definition, roleArn=exec_role_arn, type="STANDARD",
            tags=[{"key": _FORBIDDEN_KEY, "value": _FORBIDDEN_VALUE}],
        ),
        extract_arn=lambda r: r["stateMachineArn"],
        delete=lambda arn: sfn.delete_state_machine(stateMachineArn=arn),
    )
    assert (code, message) == denied(bad_sm_arn_b, session_arn_b), (
        f"ResourceTag-denied CreateStateMachine: expected {denied(bad_sm_arn_b, session_arn_b)!r}, "
        f"got {(code, message)!r}"
    )
    describe_code = _error_code(lambda: sfn.describe_state_machine(stateMachineArn=bad_sm_arn_b))
    assert describe_code == "StateMachineDoesNotExist", (
        f"a TagResource-refused CreateStateMachine must leave no state machine; got {describe_code!r}"
    )


def _tagresource_deny_policy(condition: dict) -> dict:
    return {
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
                    "iam:PassRole",
                ],
                "Resource": "*",
            },
            {
                "Effect": "Deny",
                "Action": "states:TagResource",
                "Resource": "*",
                "Condition": condition,
            },
        ],
    }


def _create_sfn_exec_role(ctx, iam) -> str:
    role_name = ctx.unique_name("sim2real-behav-createtag-execrole-")
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


def _create_role(ctx, iam, policy, suffix: str) -> tuple[str, str]:
    role_name = ctx.unique_name(f"sim2real-behav-createtag-role-{suffix}-")
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


def _refusal(ctx, fn, *, extract_arn, delete):
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
