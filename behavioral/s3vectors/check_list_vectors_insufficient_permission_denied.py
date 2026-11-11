"""list-vectors-insufficient-permission-denied."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "list-vectors-insufficient-permission-denied"
GROUP = "overly-permissive"
SERVICES = ["s3vectors"]

# The refusal names the caller and the index it was denied on; both are values this check created.
MSG_DENIED = (
    "User: {user_arn} is not authorized to perform: s3vectors:ListVectors on resource: "
    "{index_arn} because no identity-based policy allows the s3vectors:ListVectors action"
)
# What a just-minted access key can still get while IAM propagates it: the same code, another cause.
MSG_KEY_NOT_YET_VALID = "The security token included in the request is invalid."


@tags("axis:rejection", "cap:c2", "cap:c7", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """ListVectors called by an IAM principal that was never granted s3vectors:ListVectors
    is actually denied with AccessDeniedException -- it must not fall back to an implicit
    allow and return the index contents."""
    s3v = ctx.client("s3vectors")
    bucket_name = ctx.unique_name("sim2real-s3v-perm-")
    index_name = ctx.unique_name("sim2real-idx-perm-")

    s3v.create_vector_bucket(
        vectorBucketName=bucket_name,
        tags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"},
    )
    ctx.on_cleanup(lambda: s3v.delete_vector_bucket(vectorBucketName=bucket_name))
    s3v.create_index(
        vectorBucketName=bucket_name,
        indexName=index_name,
        dataType="float32",
        dimension=4,
        distanceMetric="cosine",
        tags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"},
    )
    ctx.on_cleanup(lambda: s3v.delete_index(vectorBucketName=bucket_name, indexName=index_name))
    index_arn = s3v.get_index(vectorBucketName=bucket_name, indexName=index_name)["index"]["indexArn"]
    s3v.put_vectors(
        vectorBucketName=bucket_name,
        indexName=index_name,
        vectors=[
            {"key": "v1", "data": {"float32": [0.1, 0.2, 0.3, 0.4]}},
            {"key": "v2", "data": {"float32": [0.5, 0.6, 0.7, 0.8]}},
        ],
    )

    iam = ctx.client("iam")
    user_name = ctx.unique_name("sim2real-s3v-user-")
    user_arn = iam.create_user(UserName=user_name)["User"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_user(UserName=user_name))

    policy_name = "restricted-no-listvectors"
    # deliberately grants read-only index-metadata permissions but withholds ListVectors
    iam.put_user_policy(
        UserName=user_name,
        PolicyName=policy_name,
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": ["s3vectors:GetIndex", "s3vectors:ListIndexes"],
                        "Resource": "*",
                    }
                ],
            }
        ),
    )
    ctx.on_cleanup(lambda: iam.delete_user_policy(UserName=user_name, PolicyName=policy_name))

    key = iam.create_access_key(UserName=user_name)["AccessKey"]
    ctx.on_cleanup(
        lambda: iam.delete_access_key(UserName=user_name, AccessKeyId=key["AccessKeyId"])
    )

    restricted_client = _wait_for_active_credentials(
        ctx, key["AccessKeyId"], key["SecretAccessKey"], bucket_name
    )

    # Bounded retry, reason: the new key can reach ListIndexes before ListVectors; while it
    # propagates, ListVectors refuses it as an invalid token. A success raises in _error.
    deadline = time.monotonic() + 60.0
    while True:
        code, code_msg = _error(
            lambda: restricted_client.list_vectors(
                vectorBucketName=bucket_name, indexName=index_name
            )
        )
        if code_msg != MSG_KEY_NOT_YET_VALID or time.monotonic() >= deadline:
            break
        time.sleep(2.0)
    assert code == "AccessDeniedException", (
        f"expected AccessDeniedException for a principal never granted s3vectors:ListVectors, "
        f"got {code!r}"
    )
    assert code_msg == MSG_DENIED.format(user_arn=user_arn, index_arn=index_arn), (
        f"unexpected {code!r} message {code_msg!r}"
    )

    # positive control in the same file: the fully-permissioned admin principal can list
    # the same vectors that the restricted principal was denied
    admin_keys = {
        v["key"]
        for v in s3v.list_vectors(vectorBucketName=bucket_name, indexName=index_name)["vectors"]
    }
    assert admin_keys == {"v1", "v2"}, (
        f"positive control failed: admin principal expected vectors {{'v1', 'v2'}}, got {admin_keys!r}"
    )


def _error(fn) -> tuple[str, str]:
    """Call fn(); return its botocore (code, message). An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _wait_for_active_credentials(
    ctx, access_key_id: str, secret_access_key: str, bucket_name: str, timeout_s: float = 60.0
):
    """New IAM access keys take a few seconds to propagate to s3vectors; poll an action the
    principal IS granted (ListIndexes) until it succeeds, then hand back the client. This is
    also the positive control that the restricted principal's grants are evaluated at all."""
    from botocore.exceptions import ClientError

    # ctx.client's re-signing idiom: same endpoint, TLS and retry/timeout wiring the runner
    # gave the admin clients -- only the credentials differ for the restricted principal.
    creds = {"aws_access_key_id": access_key_id, "aws_secret_access_key": secret_access_key}
    s3v_client = ctx.client("s3vectors", creds=creds)
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        try:
            s3v_client.list_indexes(vectorBucketName=bucket_name)
            return s3v_client
        except ClientError as err:
            last = f'{err.response["Error"]["Code"]}: {err.response["Error"].get("Message")}'
            time.sleep(2.0)
    raise AssertionError(f"the granted ListIndexes never succeeded for the new key (last error: {last})")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
