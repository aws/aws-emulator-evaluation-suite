"""delete-key-denied-by-iam-policy-rejected."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "delete-key-denied-by-iam-policy-rejected"
GROUP = "overly-permissive"
SERVICES = ["cloudfront-keyvaluestore"]


@tags("axis:rejection", "cap:c2", "cap:c7", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A caller with an explicit IAM Deny on cloudfront-keyvaluestore:DeleteKey for a store gets
    AccessDeniedException and the key survives; unrestricted credentials can still delete it."""
    store = _create_ready_store(ctx)
    arn = store["arn"]
    dp = ctx.client("cloudfront-keyvaluestore")
    etag = _dp_etag(dp, arn)
    seeded = dp.put_key(KvsARN=arn, Key="protected-key", Value="still-here", IfMatch=etag)

    iam = ctx.client("iam")
    user_name = ctx.unique_name("sim2real-kvsdeny-del-")
    user_arn = iam.create_user(UserName=user_name)["User"]["Arn"]
    ctx.on_cleanup(lambda: _safe(lambda: iam.delete_user(UserName=user_name)))

    policy_name = "deny-deletekey"
    policy_doc = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Action": "cloudfront-keyvaluestore:*", "Resource": "*"},
            {"Effect": "Deny", "Action": "cloudfront-keyvaluestore:DeleteKey", "Resource": arn},
        ],
    }
    iam.put_user_policy(UserName=user_name, PolicyName=policy_name, PolicyDocument=json.dumps(policy_doc))
    ctx.on_cleanup(lambda: _safe(lambda: iam.delete_user_policy(UserName=user_name, PolicyName=policy_name)))

    access_key = iam.create_access_key(UserName=user_name)["AccessKey"]
    ctx.on_cleanup(
        lambda: _safe(lambda: iam.delete_access_key(UserName=user_name, AccessKeyId=access_key["AccessKeyId"]))
    )

    limited = ctx.client(
        "cloudfront-keyvaluestore",
        creds={
            "aws_access_key_id": access_key["AccessKeyId"],
            "aws_secret_access_key": access_key["SecretAccessKey"],
        },
    )

    def _attempt():
        limited.delete_key(KvsARN=arn, Key="protected-key", IfMatch=seeded["ETag"])

    err = _wait_for_stable_error(_attempt, timeout_s=90.0, interval_s=3.0)
    assert err == (
        "AccessDeniedException",
        f"User: {user_arn} is not authorized to perform: cloudfront-keyvaluestore:DeleteKey on resource: "
        f"{arn} with an explicit deny in an identity-based policy",
    ), f"expected AccessDeniedException, got {err!r}"

    # effect absent: the denied delete never landed
    assert dp.get_key(KvsARN=arn, Key="protected-key")["Value"] == "still-here"

    # positive control: the harness's own unrestricted credentials can still delete it
    dp.delete_key(KvsARN=arn, Key="protected-key", IfMatch=seeded["ETag"])
    not_found = _error(lambda: dp.get_key(KvsARN=arn, Key="protected-key"))
    assert not_found == ("ResourceNotFoundException", "No such Key exists"), not_found


def _safe(fn) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _wait_for_stable_error(fn, timeout_s=90.0, interval_s=3.0):
    """Retry fn() until it fails with a non-transient error; return its (code, message).
    Tolerates IAM lag on new credentials and on a just-added Deny (success is retried).
    Raises AssertionError when no such error arrives before the deadline."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    last = "the call kept succeeding"
    while time.monotonic() < deadline:
        try:
            fn()
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code not in ("InvalidClientTokenId", "UnrecognizedClientException"):
                return code, e.response["Error"].get("Message")
            last = f"last error code={code}"
        time.sleep(interval_s)
    raise AssertionError(f"call was never rejected within {timeout_s}s: {last}")


def _wait_for_store_ready(ctx, name, timeout_s=180.0, interval_s=3.0):
    cf = ctx.client("cloudfront")
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        d = cf.describe_key_value_store(Name=name)
        status = d["KeyValueStore"]["Status"].upper()
        if status == "READY":
            return
        assert "FAIL" not in status, f"store entered a failure status: {status}"
        time.sleep(interval_s)
    raise AssertionError(f"store never reached READY within timeout, last status={status}")


def _create_ready_store(ctx):
    cf = ctx.client("cloudfront")
    name = ctx.unique_name("sim2real-kvs-")
    resp = cf.create_key_value_store(Name=name, Comment="sim2real behavioral check")
    arn = resp["KeyValueStore"]["ARN"]

    def _cleanup() -> None:
        d = cf.describe_key_value_store(Name=name)
        cf.delete_key_value_store(Name=name, IfMatch=d["ETag"])

    ctx.on_cleanup(_cleanup)
    _wait_for_store_ready(ctx, name)
    return {"name": name, "arn": arn}


def _dp_etag(dp, arn):
    return dp.describe_key_value_store(KvsARN=arn)["ETag"]


def _error(fn):
    """(code, message) of the ClientError fn() raises; an AssertionError when it succeeds."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
