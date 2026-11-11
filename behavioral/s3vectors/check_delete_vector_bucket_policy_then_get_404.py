"""delete-vector-bucket-policy-then-get-404."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-vector-bucket-policy-then-get-404"
GROUP = "state-machine"
SERVICES = ["s3vectors"]

MSG_POLICY_NOT_FOUND = "The specified vector bucket policy could not be found"


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """After DeleteVectorBucketPolicy, GetVectorBucketPolicy on the same bucket returns
    NotFoundException -- and the bucket itself is not broken by the delete: a fresh policy
    can still be attached to it and read back."""
    s3v = ctx.client("s3vectors")
    sts = ctx.client("sts")

    bucket_name = ctx.unique_name("sim2real-s3v-")
    bucket_arn = s3v.create_vector_bucket(vectorBucketName=bucket_name)["vectorBucketArn"]
    ctx.on_cleanup(lambda: s3v.delete_vector_bucket(vectorBucketName=bucket_name))

    account_id = sts.get_caller_identity()["Account"]

    def _policy_doc(sid: str) -> dict:
        return {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": sid,
                    "Effect": "Allow",
                    "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                    "Action": "s3vectors:GetVectorBucketPolicy",
                    "Resource": bucket_arn,
                }
            ],
        }

    policy = _policy_doc("AllowSelfGetPolicy")
    s3v.put_vector_bucket_policy(vectorBucketName=bucket_name, policy=json.dumps(policy))

    # confirm the policy actually attached before we delete it
    attached = json.loads(s3v.get_vector_bucket_policy(vectorBucketName=bucket_name)["policy"])
    assert attached == policy, f"expected the attached policy to be {policy!r}, got {attached!r}"

    s3v.delete_vector_bucket_policy(vectorBucketName=bucket_name)

    code, code_msg = _error(lambda: s3v.get_vector_bucket_policy(vectorBucketName=bucket_name))
    assert code == "NotFoundException", f"expected NotFoundException after delete, got {code!r}"
    assert code_msg == MSG_POLICY_NOT_FOUND, f"unexpected {code!r} message {code_msg!r}"

    # the policy slot is gone, not the bucket: a fresh policy can be attached and
    # read back through the same two operations that just proved the old one gone.
    second_policy = _policy_doc("AllowSelfGetPolicyAgain")
    s3v.put_vector_bucket_policy(vectorBucketName=bucket_name, policy=json.dumps(second_policy))
    reattached = json.loads(s3v.get_vector_bucket_policy(vectorBucketName=bucket_name)["policy"])
    assert reattached == second_policy, (
        f"expected the bucket to accept a fresh policy after the delete, got {reattached!r}"
    )


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
