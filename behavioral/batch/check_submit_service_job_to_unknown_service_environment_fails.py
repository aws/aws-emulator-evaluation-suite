"""submit-service-job-to-unknown-service-environment-fails."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "submit-service-job-to-unknown-service-environment-fails"
GROUP = "error-semantics"
SERVICES = ["batch"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """SubmitServiceJob referencing a job queue (and therefore the service environment
    chain behind it) that does not exist is rejected synchronously with ClientException
    naming the missing queue, and mints no service job."""
    batch = ctx.client("batch")
    bogus_queue = ctx.unique_name("sim2real-batch-no-such-queue-")
    payload = json.dumps(
        {
            "TrainingJobName": ctx.unique_name("sim2real-batch-no-such-tj-"),
            "RoleArn": f"arn:aws:iam::{ctx.account}:role/{ctx.unique_name('sim2real-batch-no-such-role-')}",
            "AlgorithmSpecification": {
                "TrainingInputMode": "File",
                "TrainingImage": f"123456789012.dkr.ecr.{ctx.region}.amazonaws.com/pytorch-training:2.1.0-cpu-py310",
                "ContainerEntrypoint": ["sleep", "60"],
            },
            "ResourceConfig": {"InstanceType": "ml.m5.large", "InstanceCount": 1, "VolumeSizeInGB": 1},
            "OutputDataConfig": {"S3OutputPath": "s3://sim2real-batch-no-such-bucket/output"},
            "StoppingCondition": {"MaxRuntimeInSeconds": 60},
        }
    )

    error = _error(
        lambda: batch.submit_service_job(
            jobName=ctx.unique_name("sim2real-batch-sj-negative-"),
            jobQueue=bogus_queue,
            serviceJobType="SAGEMAKER_TRAINING",
            serviceRequestPayload=payload,
            # quotaShareName and schedulingPriority are supplied so that the only broken
            # precondition is the non-existent job queue.
            quotaShareName=ctx.unique_name("sim2real-batch-no-such-qs-"),
            schedulingPriority=10,
        )
    )
    code, message = error.get("Code"), error.get("Message")
    assert code == "ClientException", (
        f"expected ClientException for a non-existent jobQueue, got code={code!r} message={message!r}"
    )
    assert message == f"JobQueue {bogus_queue} not found.", (
        f"expected the exact queue-not-found message naming {bogus_queue!r}, got {message!r}"
    )


def _error(fn):
    """Call fn(); return its botocore Error dict. An unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

