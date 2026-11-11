"""deploy-experiment-template-via-cloudformation-starts-experiment."""
from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-experiment-template-via-cloudformation-starts-experiment"
GROUP = "deploy"
SERVICES = ["fis"]

_TERMINAL = {"completed", "stopped", "failed", "cancelled"}


# timing:real-time — workflow: 60 s https://docs.aws.amazon.com/fis/latest/userguide/fis-actions-reference.html
@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:deploy", "concern:representation", "dp:api", "plane:data", "resource:account-singleton:fis-active-experiment-quota", "timing:real-time")
def run(ctx) -> None:
    """An AWS::FIS::ExperimentTemplate deployed via CloudFormation reaches
    CREATE_COMPLETE, and the CFN-defined action actually drives a real
    StartExperiment run to completion (observed via GetExperiment)."""
    iam = ctx.client("iam")
    fis = ctx.client("fis")
    cfn = ctx.client("cloudformation")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    # Execution role FIS assumes to run the experiment. The "wait" action needs no
    # resource permissions at all, so this role only needs the trust policy.
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "fis.amazonaws.com"},
                "Action": "sts:AssumeRole",
                "Condition": {
                    "StringEquals": {"aws:SourceAccount": account_id},
                    "ArnLike": {
                        "aws:SourceArn": f"arn:aws:fis:{ctx.region}:{account_id}:experiment/*"
                    },
                },
            }
        ],
    }
    role_name = ctx.unique_name("sim2real-fis-exec-")
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[
            {"Key": "sim2real:managed", "Value": "true"},
            {"Key": "sim2real:prefix", "Value": "sim2real-fis-exec"},
        ],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: _delete_role(ctx, role_name))
    iam.get_waiter("role_exists").wait(RoleName=role_name, WaiterConfig={"Delay": 2, "MaxAttempts": 10})

    stack_name = ctx.unique_name("sim2real-fis-cfn-")
    template = {
        "Parameters": {"RoleArn": {"Type": "String"}},
        "Resources": {
            "ExperimentTemplate": {
                "Type": "AWS::FIS::ExperimentTemplate",
                "Properties": {
                    "Description": "sim2real fis cfn deploy check",
                    "Actions": {"Wait": {"ActionId": "aws:fis:wait", "Parameters": {"duration": "PT1M"}}},
                    "Targets": {},
                    "StopConditions": [{"Source": "none"}],
                    "RoleArn": {"Ref": "RoleArn"},
                    "Tags": {"Name": "sim2real-fis-cfn-deploy"},
                },
            }
        },
        "Outputs": {"TemplateId": {"Value": {"Ref": "ExperimentTemplate"}}},
    }
    cfn.create_stack(
        StackName=stack_name,
        TemplateBody=json.dumps(template),
        Parameters=[{"ParameterKey": "RoleArn", "ParameterValue": role_arn}],
    )
    ctx.on_cleanup(lambda: _delete_stack(ctx, stack_name))
    cfn.get_waiter("stack_create_complete").wait(
        StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 150}
    )
    stack = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]
    assert stack["StackStatus"] == "CREATE_COMPLETE", f"expected CREATE_COMPLETE, got {stack['StackStatus']!r}"
    template_id = next(
        o["OutputValue"] for o in stack["Outputs"] if o["OutputKey"] == "TemplateId"
    )

    # GetExperimentTemplate: the CFN-defined action/role actually persisted server-side.
    tmpl = fis.get_experiment_template(id=template_id)["experimentTemplate"]
    assert tmpl["actions"]["Wait"]["actionId"] == "aws:fis:wait", tmpl["actions"].get("Wait")
    assert tmpl["actions"]["Wait"]["parameters"]["duration"] == "PT1M", tmpl["actions"]["Wait"].get("parameters")
    assert tmpl["roleArn"] == role_arn, f"expected roleArn {role_arn!r}, got {tmpl['roleArn']!r}"

    experiment_id = _start_experiment_with_retry(ctx, template_id)
    ctx.on_cleanup(lambda: _best_effort_stop(ctx, experiment_id))

    final = _poll_experiment_terminal(ctx, experiment_id, timeout_s=180)
    assert final["state"]["status"] == "completed", final["state"]
    assert final["experimentTemplateId"] == template_id, (
        f"expected experimentTemplateId {template_id!r}, got {final['experimentTemplateId']!r}"
    )
    # GetExperiment: the CFN-defined action is what actually ran.
    assert final["actions"]["Wait"]["actionId"] == "aws:fis:wait", final["actions"].get("Wait")
    assert final["actions"]["Wait"]["parameters"]["duration"] == "PT1M", final["actions"]["Wait"].get("parameters")


# ===== helpers =====


def _delete_role(ctx: Any, role_name: str) -> None:
    iam = ctx.client("iam")
    try:
        iam.delete_role(RoleName=role_name)
    except ClientError as e:
        if e.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _delete_stack(ctx: Any, stack_name: str) -> None:
    cfn = ctx.client("cloudformation")
    cfn.delete_stack(StackName=stack_name)
    cfn.get_waiter("stack_delete_complete").wait(
        StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 150}
    )


def _best_effort_stop(ctx: Any, experiment_id: str) -> None:
    fis = ctx.client("fis")
    try:
        exp = fis.get_experiment(id=experiment_id)["experiment"]
        if exp["state"]["status"] not in _TERMINAL:
            fis.stop_experiment(id=experiment_id)
    except ClientError as e:
        if e.response["Error"]["Code"] == "ResourceNotFoundException":
            return
        # an experiment already in a final state rejects StopExperiment; it needs no stop
        status = fis.get_experiment(id=experiment_id)["experiment"]["state"]["status"]
        if status not in _TERMINAL | {"stopping"}:
            raise


def _start_experiment_with_retry(
    ctx: Any, template_id: str, timeout_s: float = 60.0, interval_s: float = 5.0
) -> str:
    # A just-created IAM role's trust policy can lag a few seconds before AWS FIS
    # can reliably assume it (IAM is eventually consistent). Retry StartExperiment
    # with a fresh clientToken on ConflictException/ValidationException until the
    # role is usable, rather than failing on a transient propagation window.
    fis = ctx.client("fis")
    deadline = time.monotonic() + timeout_s
    last_code = None
    while time.monotonic() < deadline:
        try:
            resp = fis.start_experiment(
                clientToken=ctx.unique_name("sim2real-fis-tok-"),
                experimentTemplateId=template_id,
            )
            return resp["experiment"]["id"]
        except ClientError as exc:
            last_code = exc.response["Error"]["Code"]
            if last_code in ("ConflictException", "ValidationException"):
                time.sleep(interval_s)
                continue
            raise
    raise AssertionError(f"StartExperiment kept failing with {last_code} for {timeout_s}s")


def _poll_experiment_terminal(
    ctx: Any, experiment_id: str, timeout_s: float = 180.0, interval_s: float = 5.0
) -> dict[str, Any]:
    fis = ctx.client("fis")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        exp = fis.get_experiment(id=experiment_id)["experiment"]
        if exp["state"]["status"] in _TERMINAL:
            return exp
        time.sleep(interval_s)
    raise AssertionError(f"experiment {experiment_id} did not reach a terminal state within {timeout_s}s")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
