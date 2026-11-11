"""put-key-denied-by-iam-policy-rejected."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "put-key-denied-by-iam-policy-rejected"
GROUP = "overly-permissive"
SERVICES = ["cloudfront-keyvaluestore"]


@tags("axis:rejection", "cap:c2", "cap:c7", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A principal that can PutKey gets AccessDeniedException once an explicit Deny on PutKey for
    the store is added, and the key is never written; removing the Deny lets the call succeed."""
    store = _create_ready_store(ctx)
    arn = store["arn"]
    dp = ctx.client("cloudfront-keyvaluestore")

    iam = ctx.client("iam")
    user_name = ctx.unique_name("sim2real-kvsdeny-")
    user_arn = iam.create_user(UserName=user_name, Tags=[{"Key": "sim2real", "Value": CHECK}])["User"]["Arn"]
    ctx.on_cleanup(lambda: _safe(lambda: iam.delete_user(UserName=user_name)))

    policy_name = "kvs-putkey-policy"
    iam.put_user_policy(
        UserName=user_name, PolicyName=policy_name, PolicyDocument=json.dumps(_policy_doc(arn, deny=False))
    )
    ctx.on_cleanup(
        lambda: _safe(lambda: iam.delete_user_policy(UserName=user_name, PolicyName=policy_name))
    )

    access_key = iam.create_access_key(UserName=user_name)["AccessKey"]
    ctx.on_cleanup(
        lambda: _safe(
            lambda: iam.delete_access_key(UserName=user_name, AccessKeyId=access_key["AccessKeyId"])
        )
    )

    # ctx.client(..., creds=...) keeps the target endpoint while signing as the limited principal.
    limited = ctx.client(
        "cloudfront-keyvaluestore",
        creds={
            "aws_access_key_id": access_key["AccessKeyId"],
            "aws_secret_access_key": access_key["SecretAccessKey"],
        },
    )

    # Positive control: the same principal, before any Deny exists, can PutKey.
    # Each attempt re-fetches the ETag: a stale IfMatch after a retry's own successful write
    # reads as a conflict, not as the credential-propagation lag the retry absorbs.
    def _attempt_control():
        limited.put_key(KvsARN=arn, Key="control-key", Value="before-break", IfMatch=_dp_etag(dp, arn))

    _wait_for_stable_success(_attempt_control, timeout_s=90.0, interval_s=3.0)
    assert dp.get_key(KvsARN=arn, Key="control-key")["Value"] == "before-break"

    # Add an explicit Deny on PutKey for this store to the same principal.
    iam.put_user_policy(
        UserName=user_name, PolicyName=policy_name, PolicyDocument=json.dumps(_policy_doc(arn, deny=True))
    )

    # A just-added Deny can take a few seconds to propagate, during which PutKey may
    # still transiently succeed. Poll with a disposable probe key -- never the
    # "denied-key" the effect-absent check below relies on being untouched -- until the
    # Deny is confirmed in effect, so a stray propagation-window write can never land
    # under the identifier that check asserts is absent.
    def _attempt_probe():
        limited.put_key(KvsARN=arn, Key="propagation-probe", Value="probe", IfMatch=_dp_etag(dp, arn))

    denied = (
        "AccessDeniedException",
        f"User: {user_arn} is not authorized to perform: cloudfront-keyvaluestore:PutKey on resource: "
        f"{arn} with an explicit deny in an identity-based policy",
    )
    probe_err = _wait_for_stable_error(_attempt_probe, timeout_s=90.0, interval_s=3.0)
    assert probe_err == denied, f"expected {denied!r}, got {probe_err!r}"

    # The Deny is confirmed in effect: one deterministic attempt on the asserted key.
    err = _error(
        lambda: limited.put_key(KvsARN=arn, Key="denied-key", Value="should-not-land", IfMatch=_dp_etag(dp, arn))
    )
    assert err == denied, f"expected {denied!r}, got {err!r}"

    # effect absent: the denied write never landed
    not_found = _error(lambda: dp.get_key(KvsARN=arn, Key="denied-key"))
    assert not_found == ("ResourceNotFoundException", "No such Key exists"), (
        f"expected ResourceNotFoundException, got {not_found!r}"
    )

    # Restore: remove the Deny from the same principal's policy; the identical call must succeed.
    iam.put_user_policy(
        UserName=user_name, PolicyName=policy_name, PolicyDocument=json.dumps(_policy_doc(arn, deny=False))
    )

    def _attempt_restored():
        limited.put_key(KvsARN=arn, Key="denied-key", Value="should-not-land", IfMatch=_dp_etag(dp, arn))

    _wait_for_stable_success(_attempt_restored, timeout_s=90.0, interval_s=3.0)
    assert dp.get_key(KvsARN=arn, Key="denied-key")["Value"] == "should-not-land"


def _policy_doc(arn: str, *, deny: bool) -> dict:
    statements = [{"Effect": "Allow", "Action": "cloudfront-keyvaluestore:*", "Resource": "*"}]
    if deny:
        statements.append(
            {"Effect": "Deny", "Action": "cloudfront-keyvaluestore:PutKey", "Resource": arn}
        )
    return {"Version": "2012-10-17", "Statement": statements}


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


def _wait_for_stable_success(fn, timeout_s=90.0, interval_s=3.0) -> None:
    """Retry fn() until it succeeds, tolerating IAM lag on new credentials and on a removed Deny.
    Raises on timeout."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    last_code = None
    while time.monotonic() < deadline:
        try:
            fn()
            return
        except ClientError as e:
            last_code = e.response["Error"]["Code"]
            if last_code in ("InvalidClientTokenId", "UnrecognizedClientException", "AccessDeniedException"):
                time.sleep(interval_s)
                continue
            raise
    raise AssertionError(f"call never succeeded within {timeout_s}s, last error code={last_code}")


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
