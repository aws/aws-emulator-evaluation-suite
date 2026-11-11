"""delete-state-machine-alias-after-sm-delete-not-found."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "delete-state-machine-alias-after-sm-delete-not-found"
GROUP = "state-machine"
SERVICES = ["stepfunctions"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """After the parent state machine is deleted, its aliases become
    unresolvable (ResourceNotFound)."""
    role_arn = _create_sfn_role(ctx)
    sm_arn = _create_state_machine(ctx, role_arn, _SIMPLE_DEFINITION, register_cleanup=False)
    sfn = ctx.client("stepfunctions")

    version_arn = sfn.publish_state_machine_version(stateMachineArn=sm_arn)["stateMachineVersionArn"]
    alias_arn = sfn.create_state_machine_alias(
        name=ctx.unique_name("sim2real-alias-"),
        routingConfiguration=[{"stateMachineVersionArn": version_arn, "weight": 100}],
    )["stateMachineAliasArn"]

    # Positive control: the alias resolves and reports the routing we just set while the
    # state machine is alive, so a later ResourceNotFound cannot be "this alias never worked".
    pre_delete = sfn.describe_state_machine_alias(stateMachineAliasArn=alias_arn)
    assert pre_delete["routingConfiguration"] == [{"stateMachineVersionArn": version_arn, "weight": 100}], (
        f"alias not routing to the published version before delete: {pre_delete['routingConfiguration']!r}"
    )

    sfn.delete_state_machine(stateMachineArn=sm_arn)

    # DeleteStateMachine is asynchronous: the parent lingers in DELETING, and its aliases stay
    # describable, for a window that can exceed a minute on real AWS.
    code, message = _poll_refusal(
        lambda: sfn.describe_state_machine_alias(stateMachineAliasArn=alias_arn),
        timeout_s=240.0,
        interval_s=3.0,
    )
    assert code == "ResourceNotFound", f"expected ResourceNotFound after parent delete, got {code}"
    assert message == f"Resource not found: '{alias_arn}'", f"unexpected ResourceNotFound message {message!r}"

    # Unusable, not just unreadable: a mutation on the same dead alias must fail identically,
    # not silently succeed against a routing table AWS has already discarded.
    mutate_code, mutate_message = _error(
        lambda: sfn.update_state_machine_alias(
            stateMachineAliasArn=alias_arn,
            routingConfiguration=[{"stateMachineVersionArn": version_arn, "weight": 100}],
        )
    )
    assert mutate_code == "ResourceNotFound", f"expected ResourceNotFound on update of dead alias, got {mutate_code}"
    assert mutate_message == f"Resource not found: '{alias_arn}'", (
        f"unexpected ResourceNotFound message on update of dead alias {mutate_message!r}"
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
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _error(fn):
    """Call fn(); return its error (code, message). An unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded: {result!r}")


def _poll_refusal(fn, *, timeout_s=60.0, interval_s=2.0):
    """Call fn() until it is refused; return the refusal's (code, message). Still succeeding at
    the deadline raises."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            last = fn()
        except ClientError as exc:
            err = exc.response["Error"]
            return err["Code"], err.get("Message")
        if time.monotonic() >= deadline:
            raise AssertionError(f"call still succeeded after {timeout_s}s; last={last!r}")
        time.sleep(interval_s)


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


def _create_state_machine(ctx, role_arn, definition, *, name=None, sm_type="STANDARD", register_cleanup=True):
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
    if register_cleanup:
        ctx.on_cleanup(lambda: _swallow(lambda: sfn.delete_state_machine(stateMachineArn=arn)))
    return arn


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
