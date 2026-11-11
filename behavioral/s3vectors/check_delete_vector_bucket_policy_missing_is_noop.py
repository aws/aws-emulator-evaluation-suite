"""delete-vector-bucket-policy-missing-is-noop."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-vector-bucket-policy-missing-is-noop"
GROUP = "error-semantics"
SERVICES = ["s3vectors"]

MSG_POLICY_NOT_FOUND = "The specified vector bucket policy could not be found"


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeleteVectorBucketPolicy on a bucket without a policy succeeds and creates no policy (the get answers
    NotFoundException with the exact message); a put policy is returned by the get, and after the delete
    the get answers the same NotFoundException."""
    s3v = ctx.client("s3vectors")
    bucket_name = ctx.unique_name("sim2real-s3v-delpol-")
    bucket_arn = s3v.create_vector_bucket(vectorBucketName=bucket_name)["vectorBucketArn"]
    ctx.on_cleanup(lambda: s3v.delete_vector_bucket(vectorBucketName=bucket_name))

    # (a) deleting a policy that never existed does not raise an error -
    # it is treated as an idempotent no-op, not rejected.
    # A ClientError here fails the check.
    s3v.delete_vector_bucket_policy(vectorBucketName=bucket_name)

    # (b) the effect is still absent: there is still no policy on the bucket
    # (the no-op delete must not have fabricated an empty policy record).
    still_missing, still_message = _error(lambda: s3v.get_vector_bucket_policy(vectorBucketName=bucket_name))
    assert still_missing == "NotFoundException", (
        f"expected NotFoundException after no-op delete, got {still_missing!r}"
    )
    assert still_message == MSG_POLICY_NOT_FOUND, f"unexpected {still_missing} message {still_message!r}"

    # (c) positive control: when a policy DOES exist, DeleteVectorBucketPolicy
    # succeeds and actually removes it.
    policy = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "AllowSelfGet",
                    "Effect": "Allow",
                    "Principal": {"AWS": "*"},
                    "Action": "s3vectors:GetVectorBucketPolicy",
                    "Resource": bucket_arn,
                    "Condition": {"StringEquals": {"aws:PrincipalAccount": bucket_arn.split(":")[4]}},
                }
            ],
        }
    )
    s3v.put_vector_bucket_policy(vectorBucketName=bucket_name, policy=policy)
    attached = s3v.get_vector_bucket_policy(vectorBucketName=bucket_name)["policy"]
    assert json.loads(attached)["Statement"][0]["Sid"] == "AllowSelfGet", (
        f"expected the just-attached policy to be echoed back, got {attached!r}"
    )
    s3v.delete_vector_bucket_policy(vectorBucketName=bucket_name)
    after_delete, after_message = _error(lambda: s3v.get_vector_bucket_policy(vectorBucketName=bucket_name))
    assert after_delete == "NotFoundException", (
        f"expected NotFoundException after deleting a real policy, got {after_delete!r}"
    )
    assert after_message == MSG_POLICY_NOT_FOUND, f"unexpected {after_delete} message {after_message!r}"


def _error(fn) -> tuple[str, str]:
    """Call fn(); return its botocore (code, message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
