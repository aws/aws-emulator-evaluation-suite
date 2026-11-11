"""sm-alias-create-describe-delete."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "sm-alias-create-describe-delete"
GROUP = "state-machine"
SERVICES = ["stepfunctions"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """An alias created against a published version is describable, and after
    deletion it resolves to ResourceNotFound."""
    role_arn = _create_sfn_role(ctx)
    sm_arn = _create_state_machine(ctx, role_arn, _SIMPLE_DEFINITION)
    sfn = ctx.client("stepfunctions")

    version_arn = sfn.publish_state_machine_version(stateMachineArn=sm_arn)["stateMachineVersionArn"]

    alias_name = ctx.unique_name("sim2real-alias-")
    alias_arn = sfn.create_state_machine_alias(
        name=alias_name,
        routingConfiguration=[{"stateMachineVersionArn": version_arn, "weight": 100}],
    )["stateMachineAliasArn"]
    ctx.on_cleanup(lambda: _swallow(lambda: sfn.delete_state_machine_alias(stateMachineAliasArn=alias_arn)))

    desc = sfn.describe_state_machine_alias(stateMachineAliasArn=alias_arn)
    assert desc["name"] == alias_name
    assert desc["routingConfiguration"] == [{"stateMachineVersionArn": version_arn, "weight": 100}]

    sfn.delete_state_machine_alias(stateMachineAliasArn=alias_arn)

    # DeleteStateMachineAlias is asynchronous: DescribeStateMachineAlias can
    # briefly keep returning the stale alias right after the delete call
    # returns, so poll for the ResourceNotFound error instead of asserting
    # immediately.
    error = _poll_until(
        lambda: _error_while_visible(lambda: sfn.describe_state_machine_alias(stateMachineAliasArn=alias_arn)),
        lambda e: e is not None and e.get("Code") == "ResourceNotFound",
        timeout_s=60.0,
        interval_s=2.0,
    )
    expected_message = f"Resource not found: '{alias_arn}'"
    assert error.get("Message") == expected_message, (
        f"expected ResourceNotFound message {expected_message!r}, got {error.get('Message')!r}"
    )

    # A mutation on the now-dead alias must also fail with the same specific
    # not-found code, not silently succeed against a phantom resource.
    update_error = _client_error(
        lambda: sfn.update_state_machine_alias(
            stateMachineAliasArn=alias_arn,
            routingConfiguration=[{"stateMachineVersionArn": version_arn, "weight": 100}],
        )
    )
    assert update_error.get("Code") == "ResourceNotFound", (
        f"expected UpdateStateMachineAlias on a deleted alias to fail with ResourceNotFound, got {update_error!r}"
    )
    expected_update = "Request references a resource that does not exist."
    assert update_error.get("Message") == expected_update, (
        f"expected ResourceNotFound message {expected_update!r}, got {update_error.get('Message')!r}"
    )


_SIMPLE_DEFINITION = {
    "Comment": "simple",
    "StartAt": "PassState",
    "States": {"PassState": {"Type": "Pass", "Result": "ok", "End": True}},
}

_SFN_TRUST_POLICY = json.dumps(
    {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "states.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
)

_SFN_INLINE_POLICY = json.dumps(
    {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": [
                    "states:StartExecution",
                    "states:DescribeExecution",
                    "states:StopExecution",
                    "states:RedriveExecution",
                    "states:DescribeStateMachine",
                ],
                "Resource": "*",
            }
        ],
    }
)


def _swallow(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchEntity", "ResourceNotFound"):
            raise


def _error_while_visible(fn):
    """A poll probe: the botocore Error dict once `fn` is refused, None while it still succeeds
    (the alias is still visible inside the delete's propagation window)."""
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as exc:
        return exc.response["Error"]
    return None


def _client_error(fn):
    """The botocore Error dict `fn` raises. An unexpected SUCCESS raises AssertionError, so a
    target accepting a call real AWS refuses never reads as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED: {result!r}")


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


def _create_sfn_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-sfn-role-")
    resp = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=_SFN_TRUST_POLICY)
    role_arn = resp["Role"]["Arn"]
    iam.put_role_policy(RoleName=role_name, PolicyName="sfn-inline", PolicyDocument=_SFN_INLINE_POLICY)

    def _cleanup():
        _swallow(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="sfn-inline"))
        _swallow(lambda: iam.delete_role(RoleName=role_name))

    ctx.on_cleanup(_cleanup)
    return role_arn


def _create_state_machine(ctx, role_arn, definition, *, name=None, sm_type="STANDARD"):
    from botocore.exceptions import ClientError

    sfn = ctx.client("stepfunctions")
    name = name or ctx.unique_name("sim2real-sfn-")
    deadline = time.monotonic() + 60.0
    last_err = None
    resp = None
    while time.monotonic() < deadline:
        try:
            resp = sfn.create_state_machine(
                name=name, definition=json.dumps(definition), roleArn=role_arn, type=sm_type
            )
            break
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "AccessDeniedException":
                last_err = exc
                time.sleep(3)
                continue
            raise
    if resp is None:
        raise AssertionError(f"could not create state machine after role propagation wait: {last_err}")
    arn = resp["stateMachineArn"]
    ctx.on_cleanup(lambda: _swallow(lambda: sfn.delete_state_machine(stateMachineArn=arn)))
    return arn


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
