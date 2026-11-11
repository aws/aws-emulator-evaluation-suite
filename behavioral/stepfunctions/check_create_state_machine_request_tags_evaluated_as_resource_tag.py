"""create-state-machine-request-tags-evaluated-as-resource-tag."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-state-machine-request-tags-evaluated-as-resource-tag"
GROUP = "enforcement"
SERVICES = ["stepfunctions"]

_SESSION_NAME = "sim2real-behav-createrestag-session"
_FORBIDDEN_KEY = "sim2real-forbidden"
_FORBIDDEN_VALUE = "blocked"


@tags("axis:rejection", "cap:c7", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A Deny on CreateStateMachine conditioned on aws:ResourceTag/K=V is evaluated against the
    state machine's own request tags, though the resource does not yet exist: a create carrying
    the forbidden tag is refused, naming CreateStateMachine, while another tag still succeeds.
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
                    "states:DeleteStateMachine",
                    "states:TagResource",
                    "iam:PassRole",
                ],
                "Resource": "*",
            },
            {
                "Effect": "Deny",
                "Action": "states:CreateStateMachine",
                "Resource": "*",
                "Condition": {
                    "StringEquals": {f"aws:ResourceTag/{_FORBIDDEN_KEY}": _FORBIDDEN_VALUE}
                },
            },
        ],
    }
    role_arn, role_name = _create_role(ctx, iam, policy)
    as_role = _client_as(ctx, _assume(sts, role_arn))
    session_arn = f"arn:aws:sts::{ctx.account}:assumed-role/{role_name}/{_SESSION_NAME}"

    definition = json.dumps({"StartAt": "Done", "States": {"Done": {"Type": "Pass", "End": True}}})

    # Positive control first: once a differently-tagged create succeeds, the policy -- Allow and
    # Deny alike -- has propagated, so the refusal that follows is an evaluation of the condition.
    ok_name = ctx.unique_name("sim2real-behav-createrestag-sm-")
    ok_arn = _poll_create(
        lambda: as_role.create_state_machine(
            name=ok_name, definition=definition, roleArn=exec_role_arn, type="STANDARD",
            tags=[{"key": "sim2real-other", "value": "allowed"}],
        )["stateMachineArn"],
        timeout_s=240.0,
    )
    ctx.on_cleanup(_teardown(lambda: sfn.delete_state_machine(stateMachineArn=ok_arn)))
    held = {t["key"]: t["value"] for t in sfn.list_tags_for_resource(resourceArn=ok_arn)["tags"]}
    assert held == {"sim2real-other": "allowed"}, (
        f"the permitted create must carry exactly its own tag; got {held!r}"
    )

    # The forbidden tag, carried only on the create request itself, is refused by name of the
    # CreateStateMachine action -- the Deny's own condition, not a TagResource side effect.
    bad_name = ctx.unique_name("sim2real-behav-createrestag-sm-")
    bad_arn = f"arn:aws:states:{ctx.region}:{ctx.account}:stateMachine:{bad_name}"
    code, message = _refusal(
        ctx,
        lambda: as_role.create_state_machine(
            name=bad_name, definition=definition, roleArn=exec_role_arn, type="STANDARD",
            tags=[{"key": _FORBIDDEN_KEY, "value": _FORBIDDEN_VALUE}],
        ),
        extract_arn=lambda r: r["stateMachineArn"],
        delete=lambda arn: sfn.delete_state_machine(stateMachineArn=arn),
    )
    expected = (
        "AccessDeniedException",
        f"User: {session_arn} is not authorized to perform: states:CreateStateMachine on "
        f"resource: {bad_arn} with an explicit deny in an identity-based policy",
    )
    assert (code, message) == expected, (
        f"forbidden-tagged CreateStateMachine: expected {expected!r}, got {(code, message)!r}"
    )
    describe_code = _error_code(lambda: sfn.describe_state_machine(stateMachineArn=bad_arn))
    assert describe_code == "StateMachineDoesNotExist", (
        f"a refused CreateStateMachine must leave no state machine; DescribeStateMachine gave {describe_code!r}"
    )

    # A second, differently-tagged create under the same policy still succeeds.
    ok_name2 = ctx.unique_name("sim2real-behav-createrestag-sm-")
    ok_arn2 = as_role.create_state_machine(
        name=ok_name2, definition=definition, roleArn=exec_role_arn, type="STANDARD",
        tags=[{"key": "sim2real-second", "value": "still-allowed"}],
    )["stateMachineArn"]
    ctx.on_cleanup(_teardown(lambda: sfn.delete_state_machine(stateMachineArn=ok_arn2)))
    held2 = {t["key"]: t["value"] for t in sfn.list_tags_for_resource(resourceArn=ok_arn2)["tags"]}
    assert held2 == {"sim2real-second": "still-allowed"}, (
        f"the second permitted create must carry exactly its own tag; got {held2!r}"
    )


def _create_sfn_exec_role(ctx, iam) -> str:
    role_name = ctx.unique_name("sim2real-behav-createrestag-execrole-")
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
    role_name = ctx.unique_name("sim2real-behav-createrestag-role-")
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
