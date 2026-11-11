"""list-vectors-access-denied-without-permission."""
from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-vectors-access-denied-without-permission"
GROUP = "overly-permissive"
SERVICES = ["s3vectors"]

# The refusal names the caller and the index it was denied on; both are values this check created.
MSG_DENIED = (
    "User: {user_arn} is not authorized to perform: s3vectors:ListVectors on resource: "
    "{index_arn} because no identity-based policy allows the s3vectors:ListVectors action"
)
# What a just-minted access key gets while IAM propagates it: the same code, a different cause.
MSG_KEY_NOT_YET_VALID = "The security token included in the request is invalid."


@tags(
    "axis:rejection",
    "cap:c2",
    "cap:c7",
    "concern:data-plane",
    "concern:negative-classes",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """ListVectors by an IAM identity with no s3vectors permissions is AccessDeniedException with the exact
    message instead of an empty listing, and after that identity is granted ListVectors the same call
    returns the index's one vector key v1."""
    s3v = ctx.client("s3vectors")

    bucket_name = ctx.unique_name("sim2real-s3v-perm-")
    index_name = ctx.unique_name("sim2real-s3v-idx-")
    s3v.create_vector_bucket(
        vectorBucketName=bucket_name, tags={"sim2real:managed": "true", "sim2real:check": CHECK}
    )
    ctx.on_cleanup(lambda: s3v.delete_vector_bucket(vectorBucketName=bucket_name))
    s3v.create_index(
        vectorBucketName=bucket_name,
        indexName=index_name,
        dataType="float32",
        dimension=4,
        distanceMetric="cosine",
    )
    ctx.on_cleanup(lambda: s3v.delete_index(vectorBucketName=bucket_name, indexName=index_name))
    index_arn = s3v.get_index(vectorBucketName=bucket_name, indexName=index_name)["index"]["indexArn"]
    s3v.put_vectors(
        vectorBucketName=bucket_name,
        indexName=index_name,
        vectors=[{"key": "v1", "data": {"float32": [0.1, 0.2, 0.3, 0.4]}}],
    )

    # Positive control: the admin/default credentials used to provision the
    # index CAN list vectors on it.
    admin_listing = s3v.list_vectors(vectorBucketName=bucket_name, indexName=index_name)
    assert "vectors" in admin_listing, f"admin listing missing 'vectors' key: {admin_listing!r}"

    user_name, user_arn, access_key, secret_key = _create_permissionless_iam_user(ctx)

    restricted = ctx.client(
        "s3vectors",
        creds={"aws_access_key_id": access_key, "aws_secret_access_key": secret_key},
    )

    def _attempt():
        return restricted.list_vectors(vectorBucketName=bucket_name, indexName=index_name)

    code, message = _poll_for_access_denied(_attempt)
    assert code == "AccessDeniedException", f"expected AccessDeniedException, got {code!r}"
    assert message == MSG_DENIED.format(user_arn=user_arn, index_arn=index_arn), (
        f"unexpected AccessDeniedException message {message!r}"
    )

    # Restore leg: attaching an explicit ListVectors grant to the SAME principal
    # must flip the identical call to success. Without this, a target that
    # blanket-denies any non-bootstrap credential (rather than evaluating the
    # attached policy) would also pass the beat above.
    iam = ctx.client("iam")
    grant_policy_name = "sim2real-grant-listvectors"
    iam.put_user_policy(
        UserName=user_name,
        PolicyName=grant_policy_name,
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {"Effect": "Allow", "Action": "s3vectors:ListVectors", "Resource": "*"}
                ],
            }
        ),
    )
    ctx.on_cleanup(lambda: iam.delete_user_policy(UserName=user_name, PolicyName=grant_policy_name))

    restored = _poll_for_success(_attempt)
    restored_keys = {v["key"] for v in restored["vectors"]}
    assert restored_keys == {"v1"}, f"expected {{'v1'}} after the grant, got {restored_keys!r}"


def _create_permissionless_iam_user(ctx) -> tuple[str, str, str, str]:
    """Creates an IAM user with NO attached policies (implicit deny on
    everything) and a fresh access key, each with its cleanup registered at once.
    Returns (user_name, user_arn, access_key, secret_key)."""
    iam = ctx.client("iam")
    user_name = ctx.unique_name("sim2real-s3v-noperm-")
    user_arn = iam.create_user(UserName=user_name, Tags=[{"Key": "sim2real", "Value": CHECK}])[
        "User"
    ]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_user(UserName=user_name))
    key = iam.create_access_key(UserName=user_name)["AccessKey"]
    ctx.on_cleanup(
        lambda: iam.delete_access_key(UserName=user_name, AccessKeyId=key["AccessKeyId"])
    )
    return user_name, user_arn, key["AccessKeyId"], key["SecretAccessKey"]


def _poll_for_access_denied(
    attempt_fn, timeout_s: float = 60.0, interval_s: float = 3.0
) -> tuple[str, str]:
    """(code, message) of the refusal a freshly-minted IAM credential's call settles on.
    New access keys can transiently return InvalidClientTokenId/InvalidAccessKeyId, or an
    AccessDeniedException whose message says the token is invalid, while IAM propagates; once the credential is live, a permissionless caller must get
    AccessDeniedException. A call that keeps SUCCEEDING raises at the deadline: an
    emulator that permits an unauthorized listing never reaches a refusal."""
    deadline = time.monotonic() + timeout_s
    last = "no attempt made"
    while time.monotonic() < deadline:
        try:
            result = attempt_fn()
        except ClientError as e:
            err = e.response["Error"]
            code, message = err["Code"], err.get("Message")
            propagating = code in ("InvalidClientTokenId", "InvalidAccessKeyId") or (
                message == MSG_KEY_NOT_YET_VALID
            )
            if not propagating:
                # AccessDeniedException, or a stable different error the caller's assert reports.
                return code, message
            last = f"{code}: {message}"
        else:
            last = f"the call SUCCEEDED and returned {result!r}"
        time.sleep(interval_s)
    raise AssertionError(f"never observed AccessDeniedException, last saw {last}")


def _poll_for_success(attempt_fn, timeout_s: float = 60.0, interval_s: float = 3.0) -> Any:
    """Polls until attempt_fn succeeds, tolerating AccessDeniedException while
    the newly-attached policy propagates. A stable, different error means the
    grant did not do what we think it did -- surface it immediately rather than
    looping."""
    deadline = time.monotonic() + timeout_s
    last_code = "no-exception-raised"
    while time.monotonic() < deadline:
        try:
            return attempt_fn()
        except ClientError as e:
            code = e.response["Error"]["Code"]
            last_code = code
            if code != "AccessDeniedException":
                raise
            time.sleep(interval_s)
    raise AssertionError(f"grant never took effect, last saw {last_code}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
