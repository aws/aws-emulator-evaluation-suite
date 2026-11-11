"""get-vector-bucket-policy-missing-rejected."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-vector-bucket-policy-missing-rejected"
GROUP = "error-semantics"
SERVICES = ["s3vectors"]

MSG_POLICY_NOT_FOUND = "The specified vector bucket policy could not be found"


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetVectorBucketPolicy on a bucket that never had a policy set returns
    NotFoundException rather than an empty policy string."""
    s3v = ctx.client("s3vectors")
    bucket_name = ctx.unique_name("sim2real-s3v-nopol-")
    s3v.create_vector_bucket(
        vectorBucketName=bucket_name,
        tags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-s3v-nopol"},
    )
    ctx.on_cleanup(lambda: s3v.delete_vector_bucket(vectorBucketName=bucket_name))

    # (a) the specific error code on a bucket with no policy attached.
    code, code_msg = _error(lambda: s3v.get_vector_bucket_policy(vectorBucketName=bucket_name))
    assert code == "NotFoundException", f"expected NotFoundException, got {code!r}"
    assert code_msg == MSG_POLICY_NOT_FOUND, f"unexpected {code!r} message {code_msg!r}"

    # (b) the effect is absent: the bucket itself is unaffected/still readable,
    # confirming the failure is specifically "no policy", not a broken bucket.
    got = s3v.get_vector_bucket(vectorBucketName=bucket_name)
    assert got["vectorBucket"]["vectorBucketName"] == bucket_name, (
        f"expected bucket {bucket_name!r} to still be readable, got {got['vectorBucket']!r}"
    )

    # (c) positive control: once a policy IS attached, GetVectorBucketPolicy
    # succeeds and returns exactly that policy, in the same file.
    statement = {
        "Sid": "AllowSelfGet",
        "Effect": "Allow",
        "Principal": {"AWS": "*"},
        "Action": "s3vectors:GetVectorBucketPolicy",
        "Resource": got["vectorBucket"]["vectorBucketArn"],
        "Condition": {
            "StringEquals": {"aws:PrincipalAccount": got["vectorBucket"]["vectorBucketArn"].split(":")[4]}
        },
    }
    policy = {"Version": "2012-10-17", "Statement": [statement]}
    s3v.put_vector_bucket_policy(vectorBucketName=bucket_name, policy=json.dumps(policy))
    fetched = json.loads(s3v.get_vector_bucket_policy(vectorBucketName=bucket_name)["policy"])
    assert fetched == policy, f"expected the exact policy just attached, got {fetched!r}"


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
