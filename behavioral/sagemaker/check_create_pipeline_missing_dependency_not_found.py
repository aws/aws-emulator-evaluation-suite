"""create-pipeline-missing-dependency-not-found."""
from __future__ import annotations

import json
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-pipeline-missing-dependency-not-found"
GROUP = "error-semantics"
SERVICES = ["sagemaker"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreatePipeline naming a missing S3 definition object is refused with ValidationException (an S3
    error message) and stores nothing (DescribePipeline: ResourceNotFound, exact message); the
    identical request succeeds once the object exists and the pipeline describes Active.
    """
    sm = ctx.client("sagemaker")
    s3 = ctx.client("s3")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    role_arn = f"arn:aws:iam::{account_id}:role/sim2real-behav-any-role-placeholder"
    bucket = _create_bucket(ctx)
    key = "sim2real-pipeline-definition.json"
    pipeline_name = ctx.unique_name("sim2real-pipeline-")

    def _create_pipeline():
        return sm.create_pipeline(
            PipelineName=pipeline_name,
            PipelineDefinitionS3Location={"Bucket": bucket, "ObjectKey": key},
            RoleArn=role_arn,
            ClientRequestToken=str(uuid.uuid4()),
        )

    code, message = _error(_create_pipeline)
    # message varies: AWS embeds the S3 request id and extended request id of its own lookup,
    # so the stable part that names S3 is graded.
    assert code == "ValidationException", f"expected ValidationException, got {code}: {message}"
    assert message and "S3" in message, f"expected an S3-access error message, got: {message}"

    # Effect absent: no pipeline was created under that name.
    describe_code, describe_message = _error(lambda: sm.describe_pipeline(PipelineName=pipeline_name))
    assert describe_code == "ResourceNotFound", f"expected ResourceNotFound, got {describe_code}"
    expected = (
        f"Pipeline 'arn:aws:sagemaker:{ctx.region}:{account_id}:pipeline/{pipeline_name}' "
        "does not exist."
    )
    assert describe_message == expected, f"expected {expected!r}, got {describe_message!r}"

    # Restore: put the S3 object at the SAME key the rejected call named, then
    # repeat the IDENTICAL call (same PipelineName, same Bucket/ObjectKey, same
    # RoleArn) and prove it succeeds -- pinning the earlier rejection to
    # the missing S3 object and nothing else.
    definition = json.dumps(
        {
            "Version": "2020-12-01",
            "Metadata": {},
            "Steps": [
                {
                    "Name": "sim2realNoopFail",
                    "Type": "Fail",
                    "Arguments": {"ErrorMessage": "sim2real-behavioral-probe-noop"},
                }
            ],
        }
    )
    s3.put_object(Bucket=bucket, Key=key, Body=definition.encode("utf-8"))
    ctx.on_cleanup(lambda: s3.delete_object(Bucket=bucket, Key=key))

    resp = _create_pipeline()
    ctx.on_cleanup(
        lambda: sm.delete_pipeline(
            PipelineName=pipeline_name, ClientRequestToken=str(uuid.uuid4())
        )
    )
    assert resp["PipelineArn"]

    # Terminal read is independent of the mutating call: DescribePipeline, not
    # CreatePipeline's own response.
    described = sm.describe_pipeline(PipelineName=pipeline_name)
    assert described["PipelineArn"] == resp["PipelineArn"], described
    assert described["PipelineStatus"] == "Active", described


def _error(fn):
    """Call fn(); return its (code, message). An unexpected SUCCESS raises, so a target that
    accepts what AWS refuses never reads as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


def _create_bucket(ctx):
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-pipeline-def-").lower().replace("_", "-")
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(
            Bucket=bucket,
            CreateBucketConfiguration={"LocationConstraint": ctx.region},
        )
    ctx.on_cleanup(lambda: s3.delete_bucket(Bucket=bucket))
    return bucket


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

