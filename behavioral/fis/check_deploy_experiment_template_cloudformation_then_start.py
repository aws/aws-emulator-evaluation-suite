"""deploy-experiment-template-cloudformation-then-start."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "deploy-experiment-template-cloudformation-then-start"
GROUP = "deploy"
SERVICES = ["fis"]

_TEMPLATE_YAML = """
AWSTemplateFormatVersion: '2010-09-09'
Parameters:
  RoleArn:
    Type: String
Resources:
  FisTemplate:
    Type: AWS::FIS::ExperimentTemplate
    Properties:
      Description: sim2real-behav-cfn-fis-template
      RoleArn: !Ref RoleArn
      StopConditions:
        - Source: none
      Targets: {}
      Actions:
        waitAction:
          ActionId: "aws:fis:wait"
          Parameters:
            duration: PT1M
      Tags:
        purpose: sim2real-behavioral
Outputs:
  TemplateId:
    Value: !Ref FisTemplate
"""


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:deploy", "dp:api", "plane:data", "resource:account-singleton:fis-active-experiment-quota")
def run(ctx) -> None:
    """A CFN-deployed FIS ExperimentTemplate can actually be started and reaches 'running'."""
    iam = ctx.client("iam")
    cfn = ctx.client("cloudformation")
    fis = ctx.client("fis")

    role_name = ctx.unique_name("sim2real-fis-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "fis.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    stack_name = ctx.unique_name("sim2real-fis-stack-")
    cfn.create_stack(
        StackName=stack_name,
        TemplateBody=_TEMPLATE_YAML,
        Parameters=[{"ParameterKey": "RoleArn", "ParameterValue": role_arn}],
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _delete_stack(cfn, stack_name))
    cfn.get_waiter("stack_create_complete").wait(StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 1800})

    outputs = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["Outputs"]
    template_id = next(o["OutputValue"] for o in outputs if o["OutputKey"] == "TemplateId")

    # The CFN-declared action/role must have actually reached FIS server-side, not just
    # echoed back through the stack's own Outputs.
    tmpl = fis.get_experiment_template(id=template_id)["experimentTemplate"]
    assert tmpl["roleArn"] == role_arn, f"expected roleArn {role_arn!r}, got {tmpl['roleArn']!r}"
    assert tmpl["actions"]["waitAction"]["actionId"] == "aws:fis:wait", (
        f"expected waitAction actionId 'aws:fis:wait', got {tmpl['actions']['waitAction']['actionId']!r}"
    )
    assert tmpl["actions"]["waitAction"]["parameters"]["duration"] == "PT1M", (
        f"expected wait duration 'PT1M', got {tmpl['actions']['waitAction']['parameters']['duration']!r}"
    )

    experiment_id = _start_experiment_retrying(ctx, fis, template_id)
    ctx.on_cleanup(lambda: _stop_experiment_quiet(fis, experiment_id))

    status = _poll_experiment_status(fis, experiment_id, {"running", "completed", "failed"}, timeout_s=90)
    assert status == "running", f"experiment never observed running (last status={status!r})"

    exp = fis.get_experiment(id=experiment_id)["experiment"]
    assert exp["experimentTemplateId"] == template_id, (
        f"expected experimentTemplateId {template_id!r}, got {exp['experimentTemplateId']!r}"
    )


# ===== helpers =====
def _delete_stack(cfn, stack_name: str) -> None:
    cfn.delete_stack(StackName=stack_name)
    cfn.get_waiter("stack_delete_complete").wait(StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 150})


def _stop_experiment_quiet(fis, experiment_id: str) -> None:
    from botocore.exceptions import ClientError

    try:
        fis.stop_experiment(id=experiment_id)
    except ClientError as e:
        if e.response["Error"]["Code"] == "ResourceNotFoundException":
            return
        # an experiment already in a final state rejects StopExperiment; it needs no stop
        status = fis.get_experiment(id=experiment_id)["experiment"]["state"]["status"]
        if status not in ("stopping", "stopped", "completed", "failed", "cancelled"):
            raise


def _start_experiment_retrying(ctx, fis, template_id: str, timeout_s: float = 30.0):
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            return fis.start_experiment(
                clientToken=ctx.unique_name("sim2real-fis-start-"), experimentTemplateId=template_id
            )["experiment"]["id"]
        except ClientError as err:
            last_err = err
            time.sleep(2)
    raise last_err


def _poll_experiment_status(fis, experiment_id: str, stop_on: set, timeout_s: float = 90.0, interval_s: float = 1.5):
    deadline = time.monotonic() + timeout_s
    last_status = None
    while time.monotonic() < deadline:
        last_status = fis.get_experiment(id=experiment_id)["experiment"]["state"]["status"]
        if last_status in stop_on:
            return last_status
        time.sleep(interval_s)
    return last_status


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
