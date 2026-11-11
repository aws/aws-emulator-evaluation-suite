"""vector-bucket-policy-document-round-trip."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "vector-bucket-policy-document-round-trip"
GROUP = "server-side"
SERVICES = ["s3vectors"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A policy document containing unicode text and nested JSON structures (Condition block,
    multi-value Action list) is returned structurally and value-identical by
    GetVectorBucketPolicy after PutVectorBucketPolicy."""
    s3v = ctx.client("s3vectors")
    bucket_name = ctx.unique_name("sim2real-s3v-")
    s3v.create_vector_bucket(vectorBucketName=bucket_name, tags={"sim2real:managed": "true"})
    ctx.on_cleanup(lambda: s3v.delete_vector_bucket(vectorBucketName=bucket_name))

    root_arn, bucket_arn = _root_and_bucket_arn(ctx, bucket_name)
    unicode_value = "Ünïcödé-team-\u56e2\u961f-\U0001f680"
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowRootWithTagCondition",
                "Effect": "Allow",
                "Principal": {"AWS": root_arn},
                "Action": ["s3vectors:GetVectorBucket", "s3vectors:ListIndexes"],
                "Resource": bucket_arn,
                "Condition": {
                    "StringEquals": {
                        "aws:PrincipalTag/team": unicode_value,
                    }
                },
            }
        ],
    }
    s3v.put_vector_bucket_policy(vectorBucketName=bucket_name, policy=json.dumps(policy))
    ctx.on_cleanup(lambda: s3v.delete_vector_bucket_policy(vectorBucketName=bucket_name))

    fetched_raw = s3v.get_vector_bucket_policy(vectorBucketName=bucket_name)["policy"]
    fetched = json.loads(fetched_raw)

    assert fetched == policy, f"policy round-trip mismatch: {fetched!r} != {policy!r}"
    got_condition_value = fetched["Statement"][0]["Condition"]["StringEquals"]["aws:PrincipalTag/team"]
    assert got_condition_value == unicode_value, (
        f"unicode condition value corrupted: {got_condition_value!r} != {unicode_value!r}"
    )
    got_actions = fetched["Statement"][0]["Action"]
    expected_actions = ["s3vectors:GetVectorBucket", "s3vectors:ListIndexes"]
    assert got_actions == expected_actions, (
        f"multi-value Action list not preserved: {got_actions!r} != {expected_actions!r}"
    )


def _root_and_bucket_arn(ctx, bucket_name: str) -> tuple[str, str]:
    identity = ctx.client("sts").get_caller_identity()
    partition = identity["Arn"].split(":")[1]
    account = identity["Account"]
    root_arn = f"arn:{partition}:iam::{account}:root"
    bucket_arn = f"arn:{partition}:s3vectors:{ctx.region}:{account}:bucket/{bucket_name}"
    return root_arn, bucket_arn


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
