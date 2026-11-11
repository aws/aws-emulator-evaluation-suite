"""deploy-vector-bucket-and-index-behaves-via-cloudformation."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "deploy-vector-bucket-and-index-behaves-via-cloudformation"
GROUP = "deploy"
SERVICES = ["s3vectors"]

_TEMPLATE = """
AWSTemplateFormatVersion: '2010-09-09'
Parameters:
  BucketName:
    Type: String
  IndexName:
    Type: String
Resources:
  VectorBucket:
    Type: AWS::S3Vectors::VectorBucket
    Properties:
      VectorBucketName: !Ref BucketName
  VectorIndex:
    Type: AWS::S3Vectors::Index
    Properties:
      VectorBucketArn: !Ref VectorBucket
      IndexName: !Ref IndexName
      DataType: float32
      Dimension: 4
      DistanceMetric: cosine
Outputs:
  IndexArn:
    Value: !GetAtt VectorIndex.IndexArn
  VectorBucketArn:
    Value: !Ref VectorBucket
"""


@tags("axis:happy-path", "cap:c2", "cap:c3", "concern:data-plane", "concern:deploy", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """A VectorBucket+Index deployed via CloudFormation accepts PutVectors and
    returns correct QueryVectors results -- proving the deployed resource is
    functional, not merely CREATE_COMPLETE."""
    cfn = ctx.client("cloudformation")
    s3v = ctx.client("s3vectors")

    stack_name = ctx.unique_name("sim2real-s3vec-cfn-")
    bucket_name = ctx.unique_name("sim2real-s3vec-cfnb-")
    index_name = ctx.unique_name("sim2real-s3vec-cfni-")

    def _cleanup_stack() -> None:
        cfn.delete_stack(StackName=stack_name)
        cfn.get_waiter("stack_delete_complete").wait(
            StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 300}
        )
        try:
            status = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"]
        except cfn.exceptions.ClientError as exc:
            # A deleted stack looked up by name answers ValidationException "... does not exist".
            if "does not exist" not in exc.response["Error"].get("Message", ""):
                raise
            status = "DELETE_COMPLETE_ABSENT"
        assert status in ("DELETE_COMPLETE", "DELETE_COMPLETE_ABSENT"), (
            f"expected stack {stack_name} deleted, got status {status!r}"
        )

    cfn.create_stack(
        StackName=stack_name,
        TemplateBody=_TEMPLATE,
        Parameters=[
            {"ParameterKey": "BucketName", "ParameterValue": bucket_name},
            {"ParameterKey": "IndexName", "ParameterValue": index_name},
        ],
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )

    ctx.on_cleanup(_cleanup_stack)

    cfn.get_waiter("stack_create_complete").wait(
        StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 300}
    )

    outputs = {
        o["OutputKey"]: o["OutputValue"]
        for o in cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["Outputs"]
    }
    index_arn = outputs["IndexArn"]

    # GetIndex on the deployed resource reflects what was requested in the template.
    index = s3v.get_index(indexArn=index_arn)["index"]
    assert index["dimension"] == 4, f"expected dimension 4, got {index['dimension']!r}"
    assert index["distanceMetric"] == "cosine", (
        f"expected distanceMetric cosine, got {index['distanceMetric']!r}"
    )

    s3v.put_vectors(
        indexArn=index_arn,
        vectors=[
            {"key": "v1", "data": {"float32": [1.0, 0.0, 0.0, 0.0]}},
            {"key": "v2", "data": {"float32": [0.0, 1.0, 0.0, 0.0]}},
        ],
    )

    deadline = time.monotonic() + 30.0
    top_key = None
    top_distance = None
    while time.monotonic() < deadline:
        result = s3v.query_vectors(
            indexArn=index_arn,
            topK=1,
            queryVector={"float32": [1.0, 0.0, 0.0, 0.0]},
            returnDistance=True,
        )
        vectors = result.get("vectors", [])
        if vectors:
            top_key = vectors[0]["key"]
            top_distance = vectors[0]["distance"]
            break
        time.sleep(2.0)

    assert top_key == "v1", f"expected nearest neighbor v1, got {top_key!r}"
    assert top_distance is not None and top_distance < 1e-6, (
        f"expected ~0 cosine distance for identical vector, got {top_distance}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
