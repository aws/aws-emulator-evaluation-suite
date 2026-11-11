"""delete-vector-bucket-policy-idempotent-not-found."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "delete-vector-bucket-policy-idempotent-not-found"
GROUP = "state-machine"
SERVICES = ["s3vectors"]

MSG_POLICY_NOT_FOUND = "The specified vector bucket policy could not be found"


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteVectorBucketPolicy succeeds on a bucket that never had a policy (GetVectorBucketPolicy answers
    NotFoundException), removes a real policy, and succeeds again when repeated; after each delete the
    get answers NotFoundException "The specified vector bucket policy could not be found"."""
    s3v = ctx.client("s3vectors")
    bucket_name = ctx.unique_name("sim2real-s3v-")
    s3v.create_vector_bucket(vectorBucketName=bucket_name)
    ctx.on_cleanup(lambda: s3v.delete_vector_bucket(vectorBucketName=bucket_name))

    # No policy has ever existed -> delete must succeed as a no-op; a ClientError fails the check.
    s3v.delete_vector_bucket_policy(vectorBucketName=bucket_name)

    # Contrast: Get on the same never-had-a-policy bucket DOES raise NotFoundException.
    get_code, get_message = _error(lambda: s3v.get_vector_bucket_policy(vectorBucketName=bucket_name))
    assert get_code == "NotFoundException", f"expected NotFoundException, got {get_code!r}"
    assert get_message == MSG_POLICY_NOT_FOUND, f"unexpected {get_code} message {get_message!r}"

    # Positive control: attach a real policy, then confirm delete actually works and removes it.
    root_arn, bucket_arn = _root_and_bucket_arn(ctx, bucket_name)
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowRootGet",
                "Effect": "Allow",
                "Principal": {"AWS": root_arn},
                "Action": "s3vectors:GetVectorBucket",
                "Resource": bucket_arn,
            }
        ],
    }
    s3v.put_vector_bucket_policy(vectorBucketName=bucket_name, policy=json.dumps(policy))
    s3v.delete_vector_bucket_policy(vectorBucketName=bucket_name)  # must not raise

    code_after, message_after = _error(lambda: s3v.get_vector_bucket_policy(vectorBucketName=bucket_name))
    assert code_after == "NotFoundException", f"expected NotFoundException after real delete, got {code_after!r}"
    assert message_after == MSG_POLICY_NOT_FOUND, f"unexpected {code_after} message {message_after!r}"

    # Repeated delete after the policy is already gone is again a silent no-op, not an error.
    # A ClientError here fails the check.
    s3v.delete_vector_bucket_policy(vectorBucketName=bucket_name)

    # Terminal read, independent of the repeat delete's own response: the policy is still absent.
    final_code, final_message = _error(lambda: s3v.get_vector_bucket_policy(vectorBucketName=bucket_name))
    assert final_code == "NotFoundException", f"expected NotFoundException after repeat no-op delete, got {final_code!r}"
    assert final_message == MSG_POLICY_NOT_FOUND, f"unexpected {final_code} message {final_message!r}"


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
