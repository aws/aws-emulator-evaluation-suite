"""create-express-state-machine-ecs-run-task-sync-rejected."""

from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-express-state-machine-ecs-run-task-sync-rejected"
GROUP = "task_integrations"
SERVICES = ["stepfunctions"]

_SFN_TRUST_POLICY = json.dumps(
    {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "states.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
)


def _swallow(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchEntity",):
            raise


def _error(fn):
    """The AWS error `fn` raised, as {"Code", "Status", "Message"}. An unexpected success raises,
    so a target that accepts what AWS refuses can never read as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        status = exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode")
        return {"Code": err.get("Code"), "Status": status, "Message": err.get("Message") or ""}
    raise AssertionError(f"expected the call to fail, but it succeeded and returned {result!r}")


def _create_sfn_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-sfn-role-")
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=_SFN_TRUST_POLICY,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]

    def _delete_role():
        for pname in iam.list_role_policies(RoleName=role_name).get("PolicyNames", []):
            try:
                iam.delete_role_policy(RoleName=role_name, PolicyName=pname)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "NoSuchEntity":
                    raise
        iam.delete_role(RoleName=role_name)

    ctx.on_cleanup(lambda: _swallow(_delete_role))
    # CreateStateMachine of a STANDARD machine whose .sync task needs the managed EventBridge
    # rule provisions that rule at create time, so the role needs it up front, not only at run.
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName="managed-rule",
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": ["events:PutRule", "events:PutTargets", "events:DescribeRule"],
                        "Resource": f"arn:aws:events:{ctx.region}:{ctx.account}:rule/"
                        "StepFunctionsGetEventsForECSTaskRule",
                    }
                ],
            }
        ),
    )
    return role_arn


def _definition(state_name: str, region: str, account: str) -> str:
    return json.dumps(
        {
            "StartAt": state_name,
            "States": {
                state_name: {
                    "Type": "Task",
                    "Resource": "arn:aws:states:::ecs:runTask.sync",
                    "Parameters": {
                        "Cluster": f"arn:aws:ecs:{region}:{account}:cluster/sim2real-fake-cluster",
                        "TaskDefinition": f"arn:aws:ecs:{region}:{account}:task-definition/"
                        "sim2real-fake-taskdef:1",
                    },
                    "End": True,
                }
            },
        }
    )


def _create_state_machine(ctx, role_arn: str, definition: str, sm_type: str, name: str):
    """CreateStateMachine, retrying AccessDeniedException while the freshly created role's
    PassRole grant propagates. Returns the create response (success path only)."""
    sfn = ctx.client("stepfunctions")
    deadline = time.monotonic() + 90.0
    last_err = None
    while time.monotonic() < deadline:
        try:
            return sfn.create_state_machine(
                name=name,
                definition=definition,
                roleArn=role_arn,
                type=sm_type,
                tags=[{"key": "sim2real", "value": CHECK}],
            )
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "AccessDeniedException":
                raise
            last_err = exc
            time.sleep(5)
    raise AssertionError(f"could not create state machine after role propagation wait: {last_err}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateStateMachine of type EXPRESS whose lone Task uses the ecs:runTask.sync integration
    pattern is refused at create with InvalidDefinition, not merely at runtime; the identical
    definition as type STANDARD creates cleanly, so the refusal is EXPRESS-specific.
    """
    sfn = ctx.client("stepfunctions")
    role_arn = _create_sfn_role(ctx)
    state_name = "RunTask"
    definition = _definition(state_name, ctx.region, ctx.account)

    # Positive control: the same resource and definition, as STANDARD, is accepted at create.
    standard_name = ctx.unique_name("sim2real-behav-sfn-standard-")
    standard_resp = _create_state_machine(ctx, role_arn, definition, "STANDARD", standard_name)
    standard_arn = standard_resp["stateMachineArn"]
    ctx.on_cleanup(lambda: sfn.delete_state_machine(stateMachineArn=standard_arn))
    described = sfn.describe_state_machine(stateMachineArn=standard_arn)
    assert described["type"] == "STANDARD", f"positive control was created as {described['type']!r}"

    express_name = ctx.unique_name("sim2real-behav-sfn-express-")
    express_err = _error(
        lambda: _create_state_machine(ctx, role_arn, definition, "EXPRESS", express_name)
    )
    expected = {
        "Code": "InvalidDefinition",
        "Status": 400,
        "Message": (
            "Invalid State Machine Definition: 'SCHEMA_VALIDATION_FAILED: Express state machine "
            f"does not support '.sync' service integration at /States/{state_name}/Resource'"
        ),
    }
    assert express_err == expected, (
        f"CreateStateMachine of an EXPRESS machine using ecs:runTask.sync: "
        f"expected {expected}, got {express_err}"
    )

    # The refusal must also mean no state machine was created under that name: it stays free
    # for a later create, which a target that minted one on a "soft" rejection would not allow.
    retry = _create_state_machine(ctx, role_arn, definition, "STANDARD", express_name)
    retry_arn = retry["stateMachineArn"]
    ctx.on_cleanup(lambda: sfn.delete_state_machine(stateMachineArn=retry_arn))


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
