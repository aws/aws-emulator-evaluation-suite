"""pipeline-create-describe-delete."""
from __future__ import annotations

import json
import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "pipeline-create-describe-delete"
GROUP = "state-machine"
SERVICES = ["sagemaker"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Pipeline transitions to Active on create and DescribePipeline 404s after delete."""
    sm = ctx.client("sagemaker")
    role_arn = _create_sagemaker_role(ctx, managed_policy_arns=["arn:aws:iam::aws:policy/AmazonSageMakerFullAccess"])
    name = ctx.unique_name("sim2real-pipeline-")

    definition = json.dumps(
        {
            "Version": "2020-12-01",
            "Steps": [
                {
                    "Name": "Sim2RealNeverExecutedFailStep",
                    "Type": "Fail",
                    "Arguments": {"ErrorMessage": "sim2real behavioral fidelity check - never executed"},
                }
            ],
        }
    )

    create_resp = sm.create_pipeline(
        PipelineName=name,
        PipelineDefinition=definition,
        ClientRequestToken=str(uuid.uuid4()),
        RoleArn=role_arn,
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    pipeline_arn = create_resp["PipelineArn"]
    ctx.on_cleanup(
        lambda: _ignore_not_found(
            lambda: sm.delete_pipeline(PipelineName=name, ClientRequestToken=str(uuid.uuid4()))
        )
    )

    described = sm.describe_pipeline(PipelineName=name)
    assert described["PipelineArn"] == pipeline_arn, (
        f"expected describe to reflect the created pipeline arn {pipeline_arn}, got {described['PipelineArn']}"
    )
    assert described["PipelineStatus"] == "Active", (
        f"expected the pipeline to reach Active, got {described['PipelineStatus']}"
    )
    assert described["RoleArn"] == role_arn, (
        f"expected describe to reflect the execution role {role_arn}, got {described['RoleArn']}"
    )
    assert "Sim2RealNeverExecutedFailStep" in described["PipelineDefinition"], (
        "expected describe to echo back the step name from the submitted definition"
    )

    sm.delete_pipeline(PipelineName=name, ClientRequestToken=str(uuid.uuid4()))

    code, message = _poll_until_gone(
        lambda: sm.describe_pipeline(PipelineName=name), timeout_s=60, interval_s=3
    )
    assert code == "ResourceNotFound", f"expected ResourceNotFound after delete, got {code}"
    assert message == f"Pipeline '{pipeline_arn}' does not exist.", message

    redelete_code, redelete_message = _error(
        lambda: sm.delete_pipeline(PipelineName=name, ClientRequestToken=str(uuid.uuid4()))
    )
    assert redelete_code == "ResourceNotFound", (
        f"expected a second delete on the already-removed pipeline to also 404, got {redelete_code}"
    )
    assert redelete_message == f"Pipeline '{pipeline_arn}' does not exist.", redelete_message


def _error(fn):
    """Call fn(); return (code, message) of its ClientError. An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message", "")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


def _ignore_not_found(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFound":
            raise


def _poll_until_gone(describe, *, timeout_s: float, interval_s: float):
    """Call describe() until it raises; return (code, message). Raises if it still succeeds
    at the deadline."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            describe()
        except ClientError as e:
            return e.response["Error"]["Code"], e.response["Error"].get("Message", "")
        if time.monotonic() >= deadline:
            raise AssertionError(f"resource still described {timeout_s}s after delete")
        time.sleep(interval_s)


def _create_sagemaker_role(ctx, managed_policy_arns=None):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-sm-role-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "sagemaker.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    role_arn = role["Role"]["Arn"]
    attached = []
    for policy_arn in managed_policy_arns or []:
        iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
        attached.append(policy_arn)

    def _cleanup():
        for policy_arn in attached:
            try:
                iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "NoSuchEntity":
                    raise
        try:
            iam.delete_role(RoleName=role_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise

    ctx.on_cleanup(_cleanup)

    # Wait for the role to be readable (basic IAM propagation) before using it.
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        try:
            iam.get_role(RoleName=role_name)
            break
        except ClientError:
            time.sleep(2)
    return role_arn


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
