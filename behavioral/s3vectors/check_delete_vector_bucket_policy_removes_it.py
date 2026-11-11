"""delete-vector-bucket-policy-removes-it."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-vector-bucket-policy-removes-it"
GROUP = "state-machine"
SERVICES = ["s3vectors"]

MSG_POLICY_NOT_FOUND = "The specified vector bucket policy could not be found"


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """After DeleteVectorBucketPolicy, GetVectorBucketPolicy on the same bucket
    transitions to NotFoundException -- the policy resource is gone, not empty."""
    s3v = ctx.client("s3vectors")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    bucket_name = ctx.unique_name("sim2real-s3v-pol-")
    s3v.create_vector_bucket(
        vectorBucketName=bucket_name,
        tags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"},
    )
    ctx.on_cleanup(lambda: s3v.delete_vector_bucket(vectorBucketName=bucket_name))

    bucket_arn = _get_bucket_arn(s3v, bucket_name)
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowRootGetPolicy",
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                "Action": "s3vectors:GetVectorBucketPolicy",
                "Resource": bucket_arn,
            }
        ],
    }

    s3v.put_vector_bucket_policy(vectorBucketName=bucket_name, policy=json.dumps(policy))

    # Confirm the policy actually attached before we delete it.
    attached = s3v.get_vector_bucket_policy(vectorBucketName=bucket_name)["policy"]
    assert json.loads(attached) == policy, f"expected attached policy {policy}, got {attached}"

    s3v.delete_vector_bucket_policy(vectorBucketName=bucket_name)

    code, message = _poll_for_error(
        lambda: s3v.get_vector_bucket_policy(vectorBucketName=bucket_name)
    )
    assert code == "NotFoundException", f"expected NotFoundException after delete, got {code!r}"
    assert message == MSG_POLICY_NOT_FOUND, f"unexpected {code} message {message!r}"

    # The policy slot is reusable, not permanently poisoned by the delete: a fresh
    # policy attaches cleanly and reads back through the same (independent) call.
    replacement = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowRootPutPolicy",
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                "Action": "s3vectors:PutVectorBucketPolicy",
                "Resource": bucket_arn,
            }
        ],
    }
    s3v.put_vector_bucket_policy(vectorBucketName=bucket_name, policy=json.dumps(replacement))
    reattached = json.loads(s3v.get_vector_bucket_policy(vectorBucketName=bucket_name)["policy"])
    assert reattached == replacement, f"expected replacement policy {replacement}, got {reattached}"


def _get_bucket_arn(s3v, bucket_name: str) -> str:
    return s3v.get_vector_bucket(vectorBucketName=bucket_name)["vectorBucket"]["vectorBucketArn"]


def _poll_for_error(fn, timeout_s: float = 30.0, interval_s: float = 1.5) -> tuple[str, str]:
    """(code, message) of the first ClientError fn() raises. A call that keeps SUCCEEDING raises at
    the deadline."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            result = fn()
        except ClientError as e:
            return e.response["Error"]["Code"], e.response["Error"].get("Message")
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"GetVectorBucketPolicy never became NotFoundException; it still returned {result!r}"
            )
        time.sleep(interval_s)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
