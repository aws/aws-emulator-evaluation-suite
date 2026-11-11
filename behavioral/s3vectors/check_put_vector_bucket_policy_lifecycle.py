"""put-vector-bucket-policy-lifecycle."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-vector-bucket-policy-lifecycle"
GROUP = "state-machine"
SERVICES = ["s3vectors"]

MSG_POLICY_NOT_FOUND = "The specified vector bucket policy could not be found"


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutVectorBucketPolicy sets a policy that Get echoes; after Delete, Get raises
    NotFoundException -- and the bucket itself is not broken by the delete: a fresh
    policy can still be attached to it and read back."""
    s3v = ctx.client("s3vectors")
    bucket_name = ctx.unique_name("sim2real-s3v-")
    s3v.create_vector_bucket(vectorBucketName=bucket_name)
    ctx.on_cleanup(lambda: s3v.delete_vector_bucket(vectorBucketName=bucket_name))

    root_arn, bucket_arn = _root_and_bucket_arn(ctx, bucket_name)
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowRootFullAccess",
                "Effect": "Allow",
                "Principal": {"AWS": root_arn},
                "Action": "s3vectors:*",
                "Resource": [bucket_arn, f"{bucket_arn}/index/*"],
            }
        ],
    }
    s3v.put_vector_bucket_policy(vectorBucketName=bucket_name, policy=json.dumps(policy))

    fetched = json.loads(
        s3v.get_vector_bucket_policy(vectorBucketName=bucket_name)["policy"]
    )
    statement = fetched["Statement"][0]
    assert statement["Sid"] == "AllowRootFullAccess", (
        f"expected Sid 'AllowRootFullAccess', got {statement.get('Sid')!r}"
    )
    assert statement["Action"] == "s3vectors:*", (
        f"expected Action 's3vectors:*', got {statement.get('Action')!r}"
    )
    resource_set = set(statement["Resource"])
    expected_resources = {bucket_arn, f"{bucket_arn}/index/*"}
    assert resource_set == expected_resources, (
        f"expected Resource set {expected_resources!r}, got {resource_set!r}"
    )

    s3v.delete_vector_bucket_policy(vectorBucketName=bucket_name)

    code, code_msg = _error(lambda: s3v.get_vector_bucket_policy(vectorBucketName=bucket_name))
    assert code == "NotFoundException", f"expected NotFoundException after delete, got {code!r}"
    assert code_msg == MSG_POLICY_NOT_FOUND, f"unexpected {code!r} message {code_msg!r}"

    # the policy slot is gone, not the bucket: a fresh policy can be attached and
    # read back through the same two operations that just proved the old one gone.
    second_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowRootFullAccessAgain",
                "Effect": "Allow",
                "Principal": {"AWS": root_arn},
                "Action": "s3vectors:*",
                "Resource": [bucket_arn, f"{bucket_arn}/index/*"],
            }
        ],
    }
    s3v.put_vector_bucket_policy(vectorBucketName=bucket_name, policy=json.dumps(second_policy))
    reattached = json.loads(
        s3v.get_vector_bucket_policy(vectorBucketName=bucket_name)["policy"]
    )
    assert reattached["Statement"][0]["Sid"] == "AllowRootFullAccessAgain", (
        f"expected the bucket to accept a fresh policy after the delete, got {reattached!r}"
    )


def _root_and_bucket_arn(ctx, bucket_name: str) -> tuple[str, str]:
    identity = ctx.client("sts").get_caller_identity()
    partition = identity["Arn"].split(":")[1]
    account = identity["Account"]
    root_arn = f"arn:{partition}:iam::{account}:root"
    bucket_arn = f"arn:{partition}:s3vectors:{ctx.region}:{account}:bucket/{bucket_name}"
    return root_arn, bucket_arn


def _error(fn) -> tuple[str, str]:
    """Call fn(); return its botocore (code, message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
