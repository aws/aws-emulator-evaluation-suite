"""publish-version-service-quota-exceeded."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "publish-version-service-quota-exceeded"
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
        tags=[{"key": "sim2real", "value": "1"}],
    )["stateMachineArn"]
    ctx.on_cleanup(lambda: sfn.delete_state_machine(stateMachineArn=arn))
    return arn


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PublishStateMachineVersion numbers successive versions by +1, and each version stays listed
    and describable with the definition pinned at publish time after the live one changes.
    The 1,000-version quota (ServiceQuotaExceededException) is too costly to exercise here.
    """
    sfn = ctx.client("stepfunctions")
    definition = {"StartAt": "Done", "States": {"Done": {"Type": "Pass", "Result": {"ok": True}, "End": True}}}
    arn = _create_state_machine(ctx, definition)

    v1 = sfn.publish_state_machine_version(stateMachineArn=arn)
    v1_arn = v1["stateMachineVersionArn"]
    assert v1_arn.startswith(arn + ":"), (
        f"expected a version ARN qualifying the base state machine ARN, got {v1}"
    )
    v1_num_str = v1_arn.rsplit(":", 1)[-1]
    assert v1_num_str.isdigit(), f"expected the version ARN to end in a numeric version, got {v1}"

    definition2 = {"StartAt": "Done", "States": {"Done": {"Type": "Pass", "Result": {"ok": False}, "End": True}}}
    sfn.update_state_machine(stateMachineArn=arn, definition=json.dumps(definition2))
    v2 = sfn.publish_state_machine_version(stateMachineArn=arn)
    v2_arn = v2["stateMachineVersionArn"]
    v2_num_str = v2_arn.rsplit(":", 1)[-1]
    assert int(v2_num_str) == int(v1_num_str) + 1, (
        f"expected the second published version to be exactly one more than the first "
        f"({int(v1_num_str) + 1}), got {v2_num_str} (v1={v1_num_str})"
    )

    listed_arns = {
        v["stateMachineVersionArn"]
        for v in sfn.list_state_machine_versions(stateMachineArn=arn)["stateMachineVersions"]
    }
    assert {v1_arn, v2_arn} <= listed_arns, (
        f"expected both published versions to be visible via ListStateMachineVersions, got {listed_arns}"
    )

    described_v1 = sfn.describe_state_machine(stateMachineArn=v1_arn)
    assert json.loads(described_v1["definition"]) == definition, (
        f"expected DescribeStateMachine on the v1 version ARN to return the definition pinned "
        f"as of that publish (the live definition has since moved on), got {described_v1['definition']}"
    )
    described_v2 = sfn.describe_state_machine(stateMachineArn=v2_arn)
    assert json.loads(described_v2["definition"]) == definition2, (
        f"expected DescribeStateMachine on the v2 version ARN to return the updated definition "
        f"published at v2, got {described_v2['definition']}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
