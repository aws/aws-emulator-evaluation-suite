"""deploy-cfn-delete-stack-schedules-deletion."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-cfn-delete-stack-schedules-deletion"
GROUP = "state-machine"
SERVICES = ["secretsmanager"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:deploy", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CFN stack deletion purges the secret immediately (empirically, unlike a direct plain DeleteSecret
    call which only schedules deletion with a recovery window and leaves the secret describable)."""
    secret_name = ctx.unique_name("sim2real-behav-cfndel-")
    template_body = json.dumps(
        {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Parameters": {"SecretName": {"Type": "String"}},
            "Resources": {
                "MySecret": {
                    "Type": "AWS::SecretsManager::Secret",
                    "Properties": {"Name": {"Ref": "SecretName"}, "SecretString": "delete-me-value"},
                }
            },
            "Outputs": {"SecretArn": {"Value": {"Ref": "MySecret"}}},
        }
    )
    cfn = ctx.client("cloudformation")
    sm = ctx.client("secretsmanager")

    stack_name = ctx.unique_name("sim2real-behav-secmgr-stack-")
    cfn.create_stack(
        StackName=stack_name,
        TemplateBody=template_body,
        Parameters=[{"ParameterKey": "SecretName", "ParameterValue": secret_name}],
        Capabilities=["CAPABILITY_IAM"],
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    cfn.get_waiter("stack_create_complete").wait(
        StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 225}
    )
    stacks = cfn.describe_stacks(StackName=stack_name)["Stacks"]
    outputs = {o["OutputKey"]: o["OutputValue"] for o in stacks[0].get("Outputs", [])}
    secret_arn = outputs["SecretArn"]
    # Regardless of stack outcome, make sure the secret is fully purged afterwards.
    ctx.on_cleanup(lambda: _best_effort_purge(sm, secret_arn))

    # Before deletion the secret is active and describable.
    before = sm.describe_secret(SecretId=secret_arn)
    assert "DeletedDate" not in before, f"expected an active secret before stack deletion, got {before}"

    cfn.delete_stack(StackName=stack_name)
    cfn.get_waiter("stack_delete_complete").wait(
        StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 225}
    )

    # Empirically, CloudFormation stack deletion purges the secret outright: DescribeSecret
    # raises ResourceNotFoundException rather than returning a soft-deleted (DeletedDate-set) record.
    try:
        sm.describe_secret(SecretId=secret_arn)
        raise AssertionError("expected the secret to be fully purged after CFN stack deletion")
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code}"
        message = exc.response["Error"].get("Message")
        assert message == "Secrets Manager can't find the specified secret.", (
            f"unexpected not-found message for the purged secret: {message!r}"
        )

    # Control: a directly-created secret deleted via the plain DeleteSecret API (no
    # ForceDeleteWithoutRecovery) is only SCHEDULED for deletion -- it remains describable
    # with a DeletedDate, unlike the CFN-managed secret above. This is the direct-API semantic
    # that CFN's stack-deletion path diverges from.
    control_name = ctx.unique_name("sim2real-behav-directdel-")
    control = sm.create_secret(
        Name=control_name,
        SecretString="direct-delete-value",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    control_arn = control["ARN"]
    ctx.on_cleanup(lambda: sm.delete_secret(SecretId=control_arn, ForceDeleteWithoutRecovery=True))
    sm.delete_secret(SecretId=control_arn)
    control_after = sm.describe_secret(SecretId=control_arn)
    assert control_after["ARN"] == control_arn, (
        f"expected describe_secret to still find {control_arn}, got {control_after.get('ARN')}"
    )
    assert "DeletedDate" in control_after, "direct DeleteSecret should schedule, not purge, the secret"


def _best_effort_purge(sm, secret_arn: str) -> None:
    try:
        sm.delete_secret(SecretId=secret_arn, ForceDeleteWithoutRecovery=True)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
