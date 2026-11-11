"""vector-bucket-policy-round-trip."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "vector-bucket-policy-round-trip"
GROUP = "representation"
SERVICES = ["s3vectors"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A JSON bucket policy containing unicode and nested structures, once
    written, is returned structurally identical (no data loss/mangling) by
    GetVectorBucketPolicy."""
    s3v = ctx.client("s3vectors")
    account_id = ctx.client("sts").get_caller_identity()["Account"]

    bucket_name = ctx.unique_name("sim2real-s3vec-pol-")
    created = s3v.create_vector_bucket(
        vectorBucketName=bucket_name,
        tags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"},
    )
    ctx.on_cleanup(lambda: s3v.delete_vector_bucket(vectorBucketName=bucket_name))
    bucket_arn = created["vectorBucketArn"]

    # NOTE: IAM policy Sid elements must match [a-zA-Z0-9]+ (no unicode), so the
    # unicode/nested-structure payload is carried in Condition string values
    # instead, which accept arbitrary string content.
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowRootAccountAccess",
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                "Action": ["s3vectors:GetIndex", "s3vectors:ListIndexes"],
                "Resource": bucket_arn,
                "Condition": {
                    "StringEquals": {
                        "aws:ResourceAccount": account_id,
                        "s3vectors:comment": "允许来自根用户的访问-Ünïcödé-测试-café-環境",
                    },
                    "ForAllValues:StringLike": {"aws:TagKeys": ["env-*", "team-*"]},
                },
            }
        ],
    }

    s3v.put_vector_bucket_policy(
        vectorBucketName=bucket_name, policy=json.dumps(policy, ensure_ascii=False)
    )
    ctx.on_cleanup(lambda: s3v.delete_vector_bucket_policy(vectorBucketName=bucket_name))

    fetched_raw = s3v.get_vector_bucket_policy(vectorBucketName=bucket_name)["policy"]
    fetched = json.loads(fetched_raw)

    assert fetched == policy, f"policy round-trip mismatch: {fetched!r} != {policy!r}"
    comment = fetched["Statement"][0]["Condition"]["StringEquals"]["s3vectors:comment"]
    assert comment == "允许来自根用户的访问-Ünïcödé-测试-café-環境", (
        f"unicode condition value corrupted: {comment!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
