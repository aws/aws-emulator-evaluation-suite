"""put-vector-bucket-policy-overwrite-replaces-not-merges."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "put-vector-bucket-policy-overwrite-replaces-not-merges"
GROUP = "server-side"
SERVICES = ["s3vectors"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Calling PutVectorBucketPolicy a second time with a different policy document
    fully replaces the prior policy rather than merging statements, as enforced
    server-side."""
    s3v = ctx.client("s3vectors")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    bucket_name = ctx.unique_name("sim2real-s3vec-")
    bucket_arn = s3v.create_vector_bucket(
        vectorBucketName=bucket_name,
        tags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"},
    )["vectorBucketArn"]
    ctx.on_cleanup(lambda: s3v.delete_vector_bucket(vectorBucketName=bucket_name))

    principal = {"AWS": f"arn:aws:iam::{account_id}:root"}
    policy_a = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowGetVectorsOnly",
                "Effect": "Allow",
                "Principal": principal,
                "Action": "s3vectors:GetVectors",
                "Resource": bucket_arn,
            }
        ],
    }
    policy_b = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowPutVectorsOnly",
                "Effect": "Allow",
                "Principal": principal,
                "Action": "s3vectors:PutVectors",
                "Resource": bucket_arn,
            }
        ],
    }

    s3v.put_vector_bucket_policy(vectorBucketName=bucket_name, policy=json.dumps(policy_a))
    applied_a = json.loads(s3v.get_vector_bucket_policy(vectorBucketName=bucket_name)["policy"])
    sids_a = [s["Sid"] for s in applied_a["Statement"]]
    assert sids_a == ["AllowGetVectorsOnly"], f"expected only the first statement after initial put, got {sids_a}"

    s3v.put_vector_bucket_policy(vectorBucketName=bucket_name, policy=json.dumps(policy_b))
    applied_b = json.loads(s3v.get_vector_bucket_policy(vectorBucketName=bucket_name)["policy"])

    sids = [s["Sid"] for s in applied_b["Statement"]]
    assert sids == ["AllowPutVectorsOnly"], f"expected only the new statement to survive, got {sids}"
    action_b = applied_b["Statement"][0]["Action"]
    assert action_b == "s3vectors:PutVectors", f"expected the new statement's action, got {action_b}"
    assert len(applied_b["Statement"]) == 1, "old statement was merged rather than replaced"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
