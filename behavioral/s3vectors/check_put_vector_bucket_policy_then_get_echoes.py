"""put-vector-bucket-policy-then-get-echoes."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "put-vector-bucket-policy-then-get-echoes"
GROUP = "data-plane"
SERVICES = ["s3vectors"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutVectorBucketPolicy persists the policy document exactly, retrievable via GetVectorBucketPolicy."""
    s3v = ctx.client("s3vectors")
    sts = ctx.client("sts")

    bucket_name = ctx.unique_name("sim2real-s3v-")
    bucket_arn = s3v.create_vector_bucket(
        vectorBucketName=bucket_name,
        tags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"},
    )["vectorBucketArn"]
    ctx.on_cleanup(lambda: s3v.delete_vector_bucket(vectorBucketName=bucket_name))

    account_id = sts.get_caller_identity()["Account"]
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "DistinctiveSidForEchoCheck",
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                "Action": ["s3vectors:ListVectors", "s3vectors:GetVectors"],
                "Resource": f"{bucket_arn}/*",
            }
        ],
    }
    s3v.put_vector_bucket_policy(vectorBucketName=bucket_name, policy=json.dumps(policy))
    ctx.on_cleanup(lambda: s3v.delete_vector_bucket_policy(vectorBucketName=bucket_name))

    fetched = json.loads(s3v.get_vector_bucket_policy(vectorBucketName=bucket_name)["policy"])
    assert fetched == policy, f"policy round-trip mismatch: {fetched!r} != {policy!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
