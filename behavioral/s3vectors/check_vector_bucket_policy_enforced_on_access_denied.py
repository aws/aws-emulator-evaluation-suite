"""vector-bucket-policy-enforced-on-access-denied."""
from __future__ import annotations

import json


from behavioral_harness import tags

CHECK = "vector-bucket-policy-enforced-on-access-denied"
GROUP = "server-side"
SERVICES = ["s3vectors"]


@tags("axis:rejection", "cap:c2", "cap:c7", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A restrictive Deny statement set via PutVectorBucketPolicy is server-side enforced against real calls."""
    s3v = ctx.client("s3vectors")
    sts = ctx.client("sts")

    bucket_name = ctx.unique_name("sim2real-s3v-")
    index_name = ctx.unique_name("sim2real-idx-")
    bucket_arn = s3v.create_vector_bucket(
        vectorBucketName=bucket_name,
        tags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-s3v"},
    )["vectorBucketArn"]
    ctx.on_cleanup(lambda: s3v.delete_vector_bucket(vectorBucketName=bucket_name))
    s3v.create_index(
        vectorBucketName=bucket_name,
        indexName=index_name,
        dataType="float32",
        dimension=4,
        distanceMetric="cosine",
    )
    ctx.on_cleanup(lambda: s3v.delete_index(vectorBucketName=bucket_name, indexName=index_name))

    s3v.put_vectors(
        vectorBucketName=bucket_name,
        indexName=index_name,
        vectors=[{"key": "probe", "data": {"float32": [1.0, 0.0, 0.0, 0.0]}}],
    )

    # baseline: before any restrictive policy, read access works normally
    baseline = s3v.get_vectors(vectorBucketName=bucket_name, indexName=index_name, keys=["probe"])["vectors"]
    assert baseline and baseline[0]["key"] == "probe", f"expected baseline read of 'probe', got {baseline}"

    identity = sts.get_caller_identity()
    account_id = identity["Account"]
    caller_arn = identity["Arn"]
    index_arn = f"{bucket_arn}/index/{index_name}"
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "DenyReadAccessForAccount",
                "Effect": "Deny",
                "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                "Action": ["s3vectors:GetVectors", "s3vectors:ListVectors"],
                "Resource": [f"{bucket_arn}/*", bucket_arn],
            }
        ],
    }
    s3v.put_vector_bucket_policy(vectorBucketName=bucket_name, policy=json.dumps(policy))
    ctx.on_cleanup(lambda: s3v.delete_vector_bucket_policy(vectorBucketName=bucket_name))

    get_err = _error(lambda: s3v.get_vectors(vectorBucketName=bucket_name, indexName=index_name, keys=["probe"]))
    assert get_err["Code"] == "AccessDeniedException", f"expected AccessDeniedException on GetVectors, got {get_err!r}"
    assert get_err.get("Message") == (
        f"User: {caller_arn} is not authorized to perform: s3vectors:GetVectors on resource: "
        f"{index_arn} with an explicit deny in a resource-based policy"
    ), f"expected the exact explicit-deny message, got {get_err.get('Message')!r}"

    list_err = _error(lambda: s3v.list_vectors(vectorBucketName=bucket_name, indexName=index_name))
    assert list_err["Code"] == "AccessDeniedException", f"expected AccessDeniedException on ListVectors, got {list_err!r}"
    assert list_err.get("Message") == (
        f"User: {caller_arn} is not authorized to perform: s3vectors:ListVectors on resource: "
        f"{index_arn} with an explicit deny in a resource-based policy"
    ), f"expected the exact explicit-deny message, got {list_err.get('Message')!r}"

    # positive control: PutVectors is not covered by the deny statement, so writes still succeed
    s3v.put_vectors(
        vectorBucketName=bucket_name,
        indexName=index_name,
        vectors=[{"key": "still-writable", "data": {"float32": [0.0, 1.0, 0.0, 0.0]}}],
    )

    # restore: removing the deny statement lifts the block, and the write that went through
    # while reads were denied is now visible through the same GetVectors call that was
    # previously refused -- proving the denial was policy-driven, not a broken write path.
    s3v.delete_vector_bucket_policy(vectorBucketName=bucket_name)
    restored = s3v.get_vectors(
        vectorBucketName=bucket_name, indexName=index_name, keys=["still-writable"]
    )["vectors"]
    assert restored and restored[0]["key"] == "still-writable", (
        f"expected 'still-writable' visible after policy removal, got {restored}"
    )


def _error(fn) -> dict:
    """Call fn() and return the botocore error (Code, Message). An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
