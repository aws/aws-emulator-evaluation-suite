"""iam-role-trust-policy-missing-lambda-principal-negative."""
from __future__ import annotations

import io
import json
import time
import zipfile

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "iam-role-trust-policy-missing-lambda-principal-negative"
GROUP = "permission-boundary"
SERVICES = ["cloudformation", "iam", "lambda", "s3"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateFunction is rejected when the execution role's trust policy allows only
    ec2.amazonaws.com to assume it (no lambda.amazonaws.com principal), the function is never
    created, and the identical call succeeds once the trust policy is fixed."""
    bad_role = _create_role(
        ctx,
        {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"}, "Action": "sts:AssumeRole"}
            ],
        },
    )
    fn_name = ctx.unique_name("sim2real-fn-")
    zip_bytes = _zip_bytes(_LAMBDA_HANDLER_S3)

    code, message = _expect_create_function_rejected(ctx, fn_name, bad_role["arn"], zip_bytes)
    assert code == "InvalidParameterValueException", f"expected InvalidParameterValueException, got {code!r}"
    expected_message = "The role defined for the function cannot be assumed by Lambda."
    assert message == expected_message, f"message {message!r} != {expected_message!r}"

    # effect absent: the function was never created
    absent_code, absent_message = _error_code(
        lambda: ctx.client("lambda").get_function(FunctionName=fn_name)
    )
    assert absent_code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException for the never-created function, got {absent_code!r}"
    )
    expected_absent = f"Function not found: arn:aws:lambda:{ctx.region}:{ctx.account}:function:{fn_name}"
    assert absent_message == expected_absent, f"message {absent_message!r} != {expected_absent!r}"

    # positive control: identical call with a role whose trust policy includes lambda succeeds
    good_role = _create_role(ctx, _LAMBDA_TRUST_POLICY)
    good_fn = _create_function_with_retry(
        ctx, ctx.unique_name("sim2real-fn-"), good_role["arn"], zip_bytes
    )
    resp = ctx.client("lambda").get_function(FunctionName=good_fn)
    state = resp["Configuration"]["State"]
    assert state == "Active", f"expected the positive-control function Active, got {state!r}"


_LAMBDA_TRUST_POLICY = {
    "Version": "2012-10-17",
    "Statement": [
        {"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}
    ],
}

_LAMBDA_HANDLER_S3 = """
import boto3


def handler(event, context):
    action = event.get("action")
    bucket = event.get("bucket")
    key = event.get("key")
    s3 = boto3.client("s3")
    try:
        if action == "get":
            resp = s3.get_object(Bucket=bucket, Key=key)
            body = resp["Body"].read().decode("utf-8")
            return {"ok": True, "body": body}
        if action == "put":
            content = event.get("content", "")
            s3.put_object(Bucket=bucket, Key=key, Body=content.encode("utf-8"))
            return {"ok": True}
        return {"ok": False, "error": "bad-action"}
    except Exception as exc:  # noqa: BLE001
        resp = getattr(exc, "response", None) or {}
        code = resp.get("Error", {}).get("Code", type(exc).__name__)
        return {"ok": False, "error": code}
"""


def _zip_bytes(handler_src: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("lambda_function.py", handler_src)
    return buf.getvalue()


def _create_role(ctx, trust_policy: dict) -> dict[str, str]:
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-role-")
    resp = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _delete_role(ctx, name))
    return {"name": name, "arn": resp["Role"]["Arn"]}


def _delete_role(ctx, role_name: str) -> None:
    iam = ctx.client("iam")
    try:
        for pol in iam.list_attached_role_policies(RoleName=role_name).get("AttachedPolicies", []):
            iam.detach_role_policy(RoleName=role_name, PolicyArn=pol["PolicyArn"])
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise
    try:
        for pname in iam.list_role_policies(RoleName=role_name).get("PolicyNames", []):
            iam.delete_role_policy(RoleName=role_name, PolicyName=pname)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise
    try:
        iam.delete_role_permissions_boundary(RoleName=role_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise
    try:
        iam.delete_role(RoleName=role_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _error_code(fn) -> tuple[str, str]:
    """``(code, message)`` of the ClientError ``fn`` raises; an unexpected success fails."""
    try:
        fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError("expected the call to be refused, but it succeeded")


def _wait_active(ctx, name: str, timeout_s: float = 90.0) -> None:
    lam = ctx.client("lambda")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = lam.get_function(FunctionName=name)
        state = resp["Configuration"]["State"]
        if state == "Active":
            return
        if state == "Failed":
            raise AssertionError(f"function {name} entered Failed state")
        time.sleep(2)
    raise AssertionError(f"function {name} never became Active within {timeout_s}s")


def _create_function_with_retry(
    ctx, name: str, role_arn: str, zip_bytes: bytes, *, timeout_s: float = 120.0
) -> str:
    lam = ctx.client("lambda")
    deadline = time.monotonic() + timeout_s
    last_exc: Exception | None = None
    while time.monotonic() < deadline:
        try:
            lam.create_function(
                FunctionName=name,
                Runtime="python3.12",
                Role=role_arn,
                Handler="lambda_function.handler",
                Code={"ZipFile": zip_bytes},
                Timeout=30,
                Tags={"sim2real-check": CHECK},
            )
            break
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            msg = exc.response["Error"].get("Message", "")
            if code == "InvalidParameterValueException" and "assum" in msg.lower():
                last_exc = exc
                time.sleep(4)
                continue
            raise
    else:
        assert last_exc is not None, f"create_function for {name} never returned and never raised"
        raise last_exc
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=name))
    _wait_active(ctx, name)
    return name


def _expect_create_function_rejected(
    ctx, name: str, role_arn: str, zip_bytes: bytes, *, attempts: int = 6, interval_s: float = 5.0
) -> tuple[str, str]:
    """Repeatedly attempt CreateFunction with a role that can never be assumed by Lambda,
    to rule out a transient IAM-propagation window and confirm a stable, permanent rejection.
    Returns the last ``(code, message)``; an unexpected success fails."""
    lam = ctx.client("lambda")
    last: tuple[str, str] = ("", "")
    for _ in range(attempts):
        try:
            lam.create_function(
                FunctionName=name,
                Runtime="python3.12",
                Role=role_arn,
                Handler="lambda_function.handler",
                Code={"ZipFile": zip_bytes},
                Timeout=30,
                Tags={"sim2real-check": CHECK},
            )
        except ClientError as exc:
            last = (exc.response["Error"]["Code"], exc.response["Error"].get("Message", ""))
            time.sleep(interval_s)
            continue
        else:
            ctx.on_cleanup(lambda n=name: lam.delete_function(FunctionName=n))
            raise AssertionError(f"CreateFunction succeeded for {name!r} with a role Lambda cannot assume")
    return last


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
