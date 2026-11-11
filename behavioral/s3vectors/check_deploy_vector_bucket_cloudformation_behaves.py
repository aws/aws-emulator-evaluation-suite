"""deploy-vector-bucket-cloudformation-behaves."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "deploy-vector-bucket-cloudformation-behaves"
GROUP = "deploy"
SERVICES = ["s3vectors"]

_TERMINAL_FAILURE_STATUSES = {
    "CREATE_FAILED",
    "ROLLBACK_COMPLETE",
    "ROLLBACK_FAILED",
    "DELETE_FAILED",
}


def _poll_stack_status(cfn, stack_name, *, timeout_s=300.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        try:
            desc = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]
        except cfn.exceptions.ClientError:
            return "DELETE_COMPLETE_ABSENT"
        status = desc["StackStatus"]
        if status.endswith("_COMPLETE") or status in _TERMINAL_FAILURE_STATUSES:
            return status
        time.sleep(interval_s)
    raise AssertionError(f"stack {stack_name} did not reach a terminal state within {timeout_s}s, last: {status}")


@tags("axis:happy-path", "cap:c2", "cap:c3", "concern:data-plane", "concern:deploy", "dp:api", "plane:data")
def run(ctx) -> None:
    """A vector bucket and index deployed purely via a CloudFormation
    template accept PutVectors and return the expected result from
    QueryVectors -- not merely CREATE_COMPLETE on the stack."""
    cfn = ctx.client("cloudformation")
    s3v = ctx.client("s3vectors")

    stack_name = ctx.unique_name("sim2real-s3v-stack-")
    bucket_name = ctx.unique_name("sim2real-s3v-cfnb-")
    index_name = ctx.unique_name("sim2real-s3v-cfni-")

    template = {
        "Resources": {
            "VecBucket": {
                "Type": "AWS::S3Vectors::VectorBucket",
                "Properties": {"VectorBucketName": bucket_name},
            },
            "VecIndex": {
                "Type": "AWS::S3Vectors::Index",
                "Properties": {
                    "VectorBucketArn": {"Ref": "VecBucket"},
                    "IndexName": index_name,
                    "DataType": "float32",
                    "Dimension": 4,
                    "DistanceMetric": "cosine",
                },
                "DependsOn": "VecBucket",
            },
        }
    }

    def _delete_stack():
        cfn.delete_stack(StackName=stack_name)
        status = _poll_stack_status(cfn, stack_name, timeout_s=300.0)
        assert status in ("DELETE_COMPLETE", "DELETE_COMPLETE_ABSENT"), (
            f"stack failed to delete cleanly: {status}"
        )

    cfn.create_stack(
        StackName=stack_name,
        TemplateBody=json.dumps(template),
        Tags=[{"Key": "sim2real-check", "Value": stack_name}],
    )

    ctx.on_cleanup(_delete_stack)

    status = _poll_stack_status(cfn, stack_name, timeout_s=300.0)
    assert status == "CREATE_COMPLETE", f"stack did not reach CREATE_COMPLETE, got {status}"

    # the deployed resources must actually behave, not just exist
    query_vec = [1.0, 0.0, 0.0, 0.0]
    s3v.put_vectors(
        vectorBucketName=bucket_name,
        indexName=index_name,
        vectors=[
            {"key": "cfn-near", "data": {"float32": query_vec}, "metadata": {"role": "near"}},
            {"key": "cfn-far", "data": {"float32": [0.0, 0.0, 0.0, 1.0]}, "metadata": {"role": "far"}},
        ],
    )

    def _query():
        return s3v.query_vectors(
            vectorBucketName=bucket_name,
            indexName=index_name,
            topK=1,
            queryVector={"float32": query_vec},
            returnMetadata=True,
        )

    deadline = time.monotonic() + 60.0
    result = _query()
    while result["vectors"] == [] and time.monotonic() < deadline:
        time.sleep(2.0)
        result = _query()

    assert len(result["vectors"]) == 1, f"expected exactly 1 result for topK=1, got {result['vectors']}"
    assert result["vectors"][0]["key"] == "cfn-near", (
        f"expected nearest neighbor 'cfn-near', got {result['vectors'][0]['key']!r}"
    )
    assert result["vectors"][0]["metadata"] == {"role": "near"}, (
        f"expected metadata {{'role': 'near'}} round-tripped from PutVectors, got {result['vectors'][0]['metadata']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
