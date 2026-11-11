"""describe-state-machine-variable-references-nested-and-version-arn."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "describe-state-machine-variable-references-nested-and-version-arn"
GROUP = "jsonata"
SERVICES = ["stepfunctions"]


def _create_sfn_role(ctx):
    """A states.amazonaws.com-assumable execution role this check creates and owns."""
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
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": "1"}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    return role_arn


def _create_state_machine(ctx, role_arn, definition):
    """CreateStateMachine, retrying only the AccessDeniedException a freshly created role
    returns until IAM propagates it."""
    sfn = ctx.client("stepfunctions")
    name = ctx.unique_name("sim2real-behav-sm-")
    deadline = time.monotonic() + 90.0
    while True:
        try:
            arn = sfn.create_state_machine(
                name=name,
                definition=json.dumps(definition),
                roleArn=role_arn,
                type="STANDARD",
                tags=[{"key": "sim2real", "value": "1"}],
            )["stateMachineArn"]
            break
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "AccessDeniedException" or time.monotonic() > deadline:
                raise
            time.sleep(3)
    ctx.on_cleanup(lambda: sfn.delete_state_machine(stateMachineArn=arn))
    return arn


# Reads "x" inside a Parallel branch and inside a Map's inline ItemProcessor, exercising
# nested (non-top-level) variable references.
_DEF_WITH_VARS = {
    "QueryLanguage": "JSONata",
    "StartAt": "Init",
    "States": {
        "Init": {"Type": "Pass", "Assign": {"x": 1}, "Next": "Branch"},
        "Branch": {
            "Type": "Parallel",
            "Branches": [
                {"StartAt": "B1", "States": {"B1": {"Type": "Pass", "Output": {"y": "{% $x %}"}, "End": True}}},
                {"StartAt": "B2", "States": {"B2": {"Type": "Pass", "Output": {"z": "{% $x %}"}, "End": True}}},
            ],
            "Next": "Mapper",
        },
        "Mapper": {
            "Type": "Map",
            "Items": "{% [1, 2] %}",
            "ItemProcessor": {
                "ProcessorConfig": {"Mode": "INLINE"},
                "StartAt": "Item",
                "States": {"Item": {"Type": "Pass", "Output": {"w": "{% $x %}"}, "End": True}},
            },
            "End": True,
        },
    },
}

# No variable references at all.
_DEF_WITHOUT_VARS = {
    "QueryLanguage": "JSONata",
    "StartAt": "Init",
    "States": {"Init": {"Type": "Pass", "End": True}},
}


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeStateMachine's variableReferences names every state that reads a variable, nested
    inside a Parallel branch or a Map's ItemProcessor and not only at the top level, and a
    version-qualified stateMachineArn reports that version's own references, not the current one.
    """
    sfn = ctx.client("stepfunctions")
    role_arn = _create_sfn_role(ctx)
    sm_arn = _create_state_machine(ctx, role_arn, _DEF_WITH_VARS)

    v1_arn = sfn.publish_state_machine_version(stateMachineArn=sm_arn)["stateMachineVersionArn"]
    ctx.on_cleanup(lambda: sfn.delete_state_machine_version(stateMachineVersionArn=v1_arn))

    sfn.update_state_machine(stateMachineArn=sm_arn, definition=json.dumps(_DEF_WITHOUT_VARS))
    v2_arn = sfn.publish_state_machine_version(stateMachineArn=sm_arn)["stateMachineVersionArn"]
    ctx.on_cleanup(lambda: sfn.delete_state_machine_version(stateMachineVersionArn=v2_arn))

    # The unqualified ARN describes the current definition, which has no variable references.
    current = sfn.describe_state_machine(stateMachineArn=sm_arn)
    assert "variableReferences" not in current, (
        f"current (updated, var-free) definition unexpectedly reported variableReferences: "
        f"{current.get('variableReferences')!r}"
    )

    # The version-qualified ARN for v1 reports v1's own nested references, not the current ones.
    v1_desc = sfn.describe_state_machine(stateMachineArn=v1_arn)
    expected_refs = {"B1": ["x"], "B2": ["x"], "Item": ["x"]}
    actual_refs = {k: sorted(v) for k, v in v1_desc.get("variableReferences", {}).items()}
    assert actual_refs == expected_refs, (
        f"expected nested variableReferences {expected_refs!r} for v1, got {actual_refs!r}"
    )

    # The version-qualified ARN for v2 reports v2's own (empty) references.
    v2_desc = sfn.describe_state_machine(stateMachineArn=v2_arn)
    assert "variableReferences" not in v2_desc, (
        f"v2, which assigns no variables, unexpectedly reported variableReferences: "
        f"{v2_desc.get('variableReferences')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
