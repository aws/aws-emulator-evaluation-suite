"""get-vector-bucket-policy-missing-not-found."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-vector-bucket-policy-missing-not-found"
GROUP = "error-semantics"
SERVICES = ["s3vectors"]

MSG_POLICY_NOT_FOUND = "The specified vector bucket policy could not be found"


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetVectorBucketPolicy on a bucket that never had a policy set returns NotFoundException,
    not an empty/absent-policy success response."""
    s3v = ctx.client("s3vectors")
    sts = ctx.client("sts")
    bucket_name = ctx.unique_name("sim2real-s3v-")
    s3v.create_vector_bucket(
        vectorBucketName=bucket_name,
        tags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"},
    )
    ctx.on_cleanup(lambda: s3v.delete_vector_bucket(vectorBucketName=bucket_name))

    code, code_msg = _error(lambda: s3v.get_vector_bucket_policy(vectorBucketName=bucket_name))
    assert code == "NotFoundException", f"expected NotFoundException for a bucket with no policy, got {code!r}"
    assert code_msg == MSG_POLICY_NOT_FOUND, f"unexpected {code!r} message {code_msg!r}"

    # Positive control (a): the same bucket resolves fine for an operation that doesn't need a policy.
    got = s3v.get_vector_bucket(vectorBucketName=bucket_name)
    assert got["vectorBucket"]["vectorBucketName"] == bucket_name, (
        f"expected the bucket to remain readable, got {got['vectorBucket'].get('vectorBucketName')!r}"
    )

    # Positive control (b) on the operation under test itself: once a policy IS attached,
    # GetVectorBucketPolicy must succeed and return exactly that policy. Without this, "returns
    # NotFoundException when no policy is set" is indistinguishable from "always returns
    # NotFoundException regardless of state".
    account_id = sts.get_caller_identity()["Account"]
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowSelfGet",
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                "Action": "s3vectors:GetVectorBucketPolicy",
                "Resource": got["vectorBucket"]["vectorBucketArn"],
            }
        ],
    }
    s3v.put_vector_bucket_policy(vectorBucketName=bucket_name, policy=json.dumps(policy))
    fetched = json.loads(s3v.get_vector_bucket_policy(vectorBucketName=bucket_name)["policy"])
    assert fetched == policy, f"expected the attached policy to round-trip exactly, expected={policy!r} actual={fetched!r}"


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
