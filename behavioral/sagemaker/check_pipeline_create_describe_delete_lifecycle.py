"""pipeline-create-describe-delete-lifecycle."""
from __future__ import annotations

import json
import time
import uuid

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "pipeline-create-describe-delete-lifecycle"
GROUP = "state-machine"
SERVICES = ["sagemaker"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreatePipeline reaches Active, DescribePipeline reflects the definition, DeletePipeline removes
    it, a second delete on the same name also 404s, and the freed name is reusable."""
    sm = ctx.client("sagemaker")
    iam = ctx.client("iam")
    role_arn = _create_execution_role(ctx, iam)

    pipeline_name = ctx.unique_name("sim2real-sm-pipeline-")
    definition = json.dumps(
        {
            "Version": "2020-12-01",
            "Steps": [
                {
                    "Name": "SimFailStep",
                    "Type": "Fail",
                    "Arguments": {"ErrorMessage": "sim2real-behavioral-check"},
                }
            ],
        }
    )

    def _create(token: str):
        return sm.create_pipeline(
            PipelineName=pipeline_name,
            ClientRequestToken=token,
            PipelineDefinition=definition,
            RoleArn=role_arn,
            Tags=[{"Key": "sim2real-check", "Value": CHECK}],
        )

    created = _retry_role_propagation(lambda: _create(str(uuid.uuid4())))
    ctx.on_cleanup(lambda: _delete_pipeline_if_present(ctx, pipeline_name))
    pipeline_arn = created["PipelineArn"]

    described = sm.describe_pipeline(PipelineName=pipeline_name)
    assert described["PipelineArn"] == pipeline_arn, f"expected arn {pipeline_arn}, got {described['PipelineArn']}"
    assert described["PipelineStatus"] == "Active", f"expected Active, got {described['PipelineStatus']}"
    assert "SimFailStep" in described["PipelineDefinition"], "expected definition round-trip to contain SimFailStep"
    assert described["RoleArn"] == role_arn, f"expected role {role_arn}, got {described['RoleArn']}"

    sm.delete_pipeline(PipelineName=pipeline_name, ClientRequestToken=str(uuid.uuid4()))

    code, message = _error(lambda: sm.describe_pipeline(PipelineName=pipeline_name))
    assert code == "ResourceNotFound", f"expected ResourceNotFound after delete, got {code!r}"
    assert message == f"Pipeline '{pipeline_arn}' does not exist.", message

    double_delete_code, double_delete_message = _error(
        lambda: sm.delete_pipeline(PipelineName=pipeline_name, ClientRequestToken=str(uuid.uuid4()))
    )
    assert double_delete_code == "ResourceNotFound", (
        f"expected a second delete of the already-deleted name to also be ResourceNotFound, got {double_delete_code!r}"
    )
    assert double_delete_message == f"Pipeline '{pipeline_arn}' does not exist.", double_delete_message

    recreated = _create(str(uuid.uuid4()))
    redescribed = sm.describe_pipeline(PipelineName=pipeline_name)
    assert redescribed["PipelineArn"] == recreated["PipelineArn"], "expected the freed name to be reusable with a matching arn"
    assert redescribed["PipelineStatus"] == "Active", (
        f"expected the recreated pipeline to reach Active, got {redescribed['PipelineStatus']}"
    )


def _delete_pipeline_if_present(ctx, pipeline_name: str) -> None:
    sm = ctx.client("sagemaker")
    try:
        sm.delete_pipeline(PipelineName=pipeline_name, ClientRequestToken=str(uuid.uuid4()))
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFound":
            raise


def _error(fn):
    """Call fn(); return (code, message) of its ClientError. An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


def _create_execution_role(ctx, iam):
    role_name = ctx.unique_name("sim2real-sm-role-")
    trust = {
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
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    role_arn = role["Role"]["Arn"]

    def _cleanup():
        try:
            iam.delete_role(RoleName=role_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise

    ctx.on_cleanup(_cleanup)
    return role_arn


def _retry_role_propagation(fn, timeout_s: float = 60.0, interval_s: float = 5.0):
    """IAM roles are eventually consistent; poll the actual create call until SageMaker can use it."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            return fn()
        except ClientError as err:
            code = err.response["Error"]["Code"]
            message = err.response["Error"].get("Message", "")
            if code == "ValidationException" and "role" in message.lower():
                last_err = err
                time.sleep(interval_s)
                continue
            raise
    if last_err is not None:
        raise last_err
    raise AssertionError("role propagation retry loop exited without a result")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
