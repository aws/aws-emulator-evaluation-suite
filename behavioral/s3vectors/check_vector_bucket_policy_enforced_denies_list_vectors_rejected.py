"""vector-bucket-policy-enforced-denies-list-vectors-rejected."""
from __future__ import annotations

import json


from behavioral_harness import tags

CHECK = "vector-bucket-policy-enforced-denies-list-vectors-rejected"
GROUP = "server-side"
SERVICES = ["s3vectors"]


@tags("axis:rejection", "cap:c7", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A vector bucket policy that denies s3vectors:ListVectors makes ListVectors fail with
    AccessDeniedException and the exact explicit-deny message, while GetIndex, which the deny does not
    cover, still succeeds on the same index."""
    s3v = ctx.client("s3vectors")
    bucket_name = ctx.unique_name("sim2real-s3v-")
    index_name = ctx.unique_name("sim2real-idx-")

    s3v.create_vector_bucket(
        vectorBucketName=bucket_name,
        tags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-s3v"},
    )
    ctx.on_cleanup(lambda: s3v.delete_vector_bucket(vectorBucketName=bucket_name))
    s3v.create_index(
        vectorBucketName=bucket_name,
        indexName=index_name,
        dataType="float32",
        dimension=8,
        distanceMetric="cosine",
        tags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-idx"},
    )
    ctx.on_cleanup(
        lambda: s3v.delete_index(vectorBucketName=bucket_name, indexName=index_name)
    )

    root_arn, bucket_arn = _root_and_bucket_arn(ctx, bucket_name)
    caller_arn = ctx.client("sts").get_caller_identity()["Arn"]
    index_arn = f"{bucket_arn}/index/{index_name}"

    allow_all_policy = json.dumps(
        {
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
    )
    deny_list_policy = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "AllowRootFullAccess",
                    "Effect": "Allow",
                    "Principal": {"AWS": root_arn},
                    "Action": "s3vectors:*",
                    "Resource": [bucket_arn, f"{bucket_arn}/index/*"],
                },
                {
                    "Sid": "DenyListVectors",
                    "Effect": "Deny",
                    "Principal": {"AWS": root_arn},
                    "Action": "s3vectors:ListVectors",
                    "Resource": index_arn,
                },
            ],
        }
    )

    # Baseline: allow-only policy in place, ListVectors succeeds.
    s3v.put_vector_bucket_policy(vectorBucketName=bucket_name, policy=allow_all_policy)
    s3v.list_vectors(vectorBucketName=bucket_name, indexName=index_name)

    # Break exactly one thing: add an explicit deny on s3vectors:ListVectors.
    s3v.put_vector_bucket_policy(vectorBucketName=bucket_name, policy=deny_list_policy)

    err = _error(lambda: s3v.list_vectors(vectorBucketName=bucket_name, indexName=index_name))
    assert err["Code"] == "AccessDeniedException", f"expected AccessDeniedException on ListVectors, got {err!r}"
    assert err.get("Message") == (
        f"User: {caller_arn} is not authorized to perform: s3vectors:ListVectors on resource: "
        f"{index_arn} with an explicit deny in a resource-based policy"
    ), f"expected the exact explicit-deny message, got {err.get('Message')!r}"

    # The deny is scoped: an action NOT covered by the deny statement still works.
    got_index = s3v.get_index(vectorBucketName=bucket_name, indexName=index_name)
    assert got_index["index"]["indexName"] == index_name, (
        f"expected GetIndex (not covered by the deny) to still succeed, "
        f"got indexName={got_index['index']['indexName']!r} vs expected {index_name!r}"
    )

    # Positive control: restoring the allow-only policy restores ListVectors access.
    s3v.put_vector_bucket_policy(vectorBucketName=bucket_name, policy=allow_all_policy)
    s3v.list_vectors(vectorBucketName=bucket_name, indexName=index_name)


def _root_and_bucket_arn(ctx, bucket_name: str) -> tuple[str, str]:
    identity = ctx.client("sts").get_caller_identity()
    partition = identity["Arn"].split(":")[1]
    account = identity["Account"]
    root_arn = f"arn:{partition}:iam::{account}:root"
    bucket_arn = f"arn:{partition}:s3vectors:{ctx.region}:{account}:bucket/{bucket_name}"
    return root_arn, bucket_arn


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
