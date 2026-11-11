"""put-vector-bucket-policy-malformed-json-rejected."""
from __future__ import annotations

import json


from behavioral_harness import tags

CHECK = "put-vector-bucket-policy-malformed-json-rejected"
GROUP = "negative-classes"
SERVICES = ["s3vectors"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutVectorBucketPolicy with syntactically invalid policy JSON is rejected
    with ValidationException rather than being accepted verbatim."""
    s3v = ctx.client("s3vectors")
    bucket_name = ctx.unique_name("sim2real-s3v-badpol-")
    bucket_arn = s3v.create_vector_bucket(
        vectorBucketName=bucket_name,
        tags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"},
    )["vectorBucketArn"]
    ctx.on_cleanup(lambda: s3v.delete_vector_bucket(vectorBucketName=bucket_name))

    malformed = '{ "Version": "2012-10-17", "Statement": [ this is not json'

    # (a) the specific error code for malformed policy JSON.
    err = _error(lambda: s3v.put_vector_bucket_policy(vectorBucketName=bucket_name, policy=malformed))
    assert err["Code"] == "ValidationException", f"expected ValidationException for malformed policy JSON, got {err!r}"
    assert err.get("Message") == "The provided policy is malformed or invalid", (
        f"expected the exact malformed-policy message, got {err.get('Message')!r}"
    )

    # (b) the effect is absent: nothing got stored as a policy.
    still_missing = _error(lambda: s3v.get_vector_bucket_policy(vectorBucketName=bucket_name))
    assert still_missing["Code"] == "NotFoundException", (
        f"expected no policy to have been stored after the rejected put, got {still_missing!r}"
    )
    assert still_missing.get("Message") == "The specified vector bucket policy could not be found", (
        f"expected the exact policy not-found message, got {still_missing.get('Message')!r}"
    )

    # (c) positive control: a syntactically valid policy on the same bucket
    # is accepted and can be read back verbatim.
    valid_policy = json.dumps(
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
    s3v.put_vector_bucket_policy(vectorBucketName=bucket_name, policy=valid_policy)
    fetched = s3v.get_vector_bucket_policy(vectorBucketName=bucket_name)["policy"]
    sid = json.loads(fetched)["Statement"][0]["Sid"]
    assert sid == "AllowSelfGet", f"expected the positive-control policy to round-trip, got Sid={sid!r}"


def _error(fn) -> dict:
    """Call fn() and return the botocore error (Code, Message). An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
