"""deploy-notebook-instance-cfn-invalid-role-rejected."""
from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags

CHECK = "deploy-notebook-instance-cfn-invalid-role-rejected"
GROUP = "deploy"
SERVICES = ["sagemaker"]

_SAGEMAKER_TRUST_POLICY = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {"Service": "sagemaker.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }
    ],
}
# Deliberately wrong: only EC2 may assume this role, not sagemaker.amazonaws.com.
_EC2_ONLY_TRUST_POLICY = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {"Service": "ec2.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }
    ],
}
_SAGEMAKER_MANAGED_POLICY_ARN = "arn:aws:iam::aws:policy/AmazonSageMakerFullAccess"


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:deploy", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A NotebookInstance stack whose role does not trust sagemaker.amazonaws.com ends
    CREATE_FAILED with the instance stuck in Failed, while the identical stack with a trusted
    role reaches CREATE_COMPLETE and InService, so the trust policy is actually validated."""
    # ml.t3.medium: ml.t2 is rejected for NotebookInstance. The positive control is what
    # keeps a backend that rejects every notebook instance from passing.
    cfn = ctx.client("cloudformation")
    iam = ctx.client("iam")
    sm = ctx.client("sagemaker")

    good_role_name = ctx.unique_name("sim2real-sagemaker-nb-goodrole-")
    good_role_arn = _create_role(ctx, iam, good_role_name, _SAGEMAKER_TRUST_POLICY)
    bad_role_name = ctx.unique_name("sim2real-sagemaker-nb-badrole-")
    bad_role_arn = _create_role(ctx, iam, bad_role_name, _EC2_ONLY_TRUST_POLICY)

    template_body = json.dumps(
        {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Parameters": {
                "RoleArn": {"Type": "String"},
                "NotebookInstanceName": {"Type": "String"},
            },
            "Resources": {
                "NotebookInstance": {
                    "Type": "AWS::SageMaker::NotebookInstance",
                    "Properties": {
                        "NotebookInstanceName": {"Ref": "NotebookInstanceName"},
                        "InstanceType": "ml.t3.medium",
                        "RoleArn": {"Ref": "RoleArn"},
                    },
                }
            },
        }
    )

    # --- positive control: a properly-trusted role deploys successfully ---
    good_notebook_name = ctx.unique_name("sim2real-sagemaker-nb-good-")
    good_stack_name = ctx.unique_name("sim2real-sagemaker-nb-good-stack-")
    ctx.on_cleanup(lambda: _delete_stack(cfn, good_stack_name, timeout_s=540.0))
    good_status = _deploy_with_role_propagation_retry(
        cfn, good_stack_name, template_body, good_role_arn, good_notebook_name
    )
    assert good_status == "CREATE_COMPLETE", f"positive control did not deploy: {good_status}"
    good_described = sm.describe_notebook_instance(NotebookInstanceName=good_notebook_name)
    assert good_described["NotebookInstanceStatus"] == "InService", (
        f"expected InService, got {good_described['NotebookInstanceStatus']}"
    )

    # --- break exactly one thing: the role's trust policy does not permit SageMaker ---
    bad_notebook_name = ctx.unique_name("sim2real-sagemaker-nb-bad-")
    bad_stack_name = ctx.unique_name("sim2real-sagemaker-nb-bad-stack-")
    cfn.create_stack(
        StackName=bad_stack_name,
        TemplateBody=template_body,
        Parameters=[
            {"ParameterKey": "RoleArn", "ParameterValue": bad_role_arn},
            {"ParameterKey": "NotebookInstanceName", "ParameterValue": bad_notebook_name},
        ],
        Tags=[{"Key": "sim2real", "Value": CHECK}],
        DisableRollback=True,
    )
    ctx.on_cleanup(lambda: _delete_stack(cfn, bad_stack_name, timeout_s=540.0))
    bad_status = _wait_for_stack_terminal(cfn, bad_stack_name, timeout_s=1800.0, interval_s=20.0)
    assert bad_status == "CREATE_FAILED", f"expected CREATE_FAILED, got {bad_status}"

    # CreateNotebookInstance is accepted synchronously and the AssumeRole failure surfaces
    # during provisioning; with rollback disabled the instance remains, stuck in Failed.
    bad_described = sm.describe_notebook_instance(NotebookInstanceName=bad_notebook_name)
    assert bad_described["NotebookInstanceStatus"] == "Failed", (
        f"expected the untrusted-role notebook instance to be stuck in Failed, "
        f"got {bad_described['NotebookInstanceStatus']!r}"
    )




def _create_role(ctx: Any, iam, role_name: str, trust_policy: dict) -> str:
    resp = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    role_arn = resp["Role"]["Arn"]
    iam.attach_role_policy(RoleName=role_name, PolicyArn=_SAGEMAKER_MANAGED_POLICY_ARN)

    def _cleanup() -> None:
        from botocore.exceptions import ClientError

        try:
            iam.detach_role_policy(RoleName=role_name, PolicyArn=_SAGEMAKER_MANAGED_POLICY_ARN)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
        iam.delete_role(RoleName=role_name)

    ctx.on_cleanup(_cleanup)
    return role_arn


def _deploy_with_role_propagation_retry(
    cfn,
    stack_name: str,
    template_body: str,
    role_arn: str,
    notebook_instance_name: str,
    attempts: int = 4,
    retry_delay_s: float = 15.0,
) -> str:
    """Retry the deploy, bounded by attempts and a per-attempt deadline, because a fresh role's
    trust policy may not yet have propagated to CloudFormation's SageMaker handler."""
    last_status = "UNKNOWN"
    for attempt in range(attempts):
        cfn.create_stack(
            StackName=stack_name,
            TemplateBody=template_body,
            Parameters=[
                {"ParameterKey": "RoleArn", "ParameterValue": role_arn},
                {"ParameterKey": "NotebookInstanceName", "ParameterValue": notebook_instance_name},
            ],
            Tags=[{"Key": "sim2real", "Value": CHECK}],
        )
        last_status = _wait_for_stack_terminal(cfn, stack_name, timeout_s=1800.0, interval_s=20.0)
        if last_status == "CREATE_COMPLETE" or attempt == attempts - 1:
            return last_status
        _delete_stack(cfn, stack_name)
        time.sleep(retry_delay_s)
    return last_status


def _wait_for_stack_terminal(cfn, stack_name: str, timeout_s: float, interval_s: float) -> str:
    deadline = time.monotonic() + timeout_s
    status = "UNKNOWN"
    while time.monotonic() < deadline:
        resp = cfn.describe_stacks(StackName=stack_name)
        status = resp["Stacks"][0]["StackStatus"]
        if status.endswith("_COMPLETE") or status.endswith("_FAILED"):
            return status
        time.sleep(interval_s)
    raise AssertionError(f"stack {stack_name} never reached a terminal status (last={status})")


def _delete_stack(cfn, stack_name: str, timeout_s: float = 1800.0) -> None:
    """Delete the stack and wait until it is gone; teardown passes a timeout within its budget."""
    from botocore.exceptions import ClientError

    cfn.delete_stack(StackName=stack_name)
    deadline = time.monotonic() + timeout_s
    status = "UNKNOWN"
    while time.monotonic() < deadline:
        try:
            resp = cfn.describe_stacks(StackName=stack_name)
        except ClientError as exc:
            error = exc.response["Error"]
            if error["Code"] == "ValidationError" and "does not exist" in error.get("Message", ""):
                return  # stack fully gone
            raise
        status = resp["Stacks"][0]["StackStatus"]
        if status == "DELETE_COMPLETE":
            return
        if status.endswith("_FAILED"):
            raise AssertionError(f"stack {stack_name} delete failed with status {status}")
        time.sleep(2.0)
    raise AssertionError(f"stack {stack_name} was not deleted within {timeout_s:.0f}s (last={status})")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
