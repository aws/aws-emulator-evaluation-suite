"""lambda-role-missing-trust-statement-negative."""
from __future__ import annotations

import io
import json
import time
import zipfile
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "lambda-role-missing-trust-statement-negative"
GROUP = "overly-permissive"
SERVICES = ["dynamodb", "events", "lambda"]

_HANDLER_STS = """
import boto3

def handler(event, context):
    sts = boto3.client("sts")
    ident = sts.get_caller_identity()
    return {"arn": ident["Arn"]}
"""


@tags("axis:rejection", "cap:c3", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:control", "plane:data")
def run(ctx) -> None:
    """CreateRole with an empty trust statement list is rejected with MalformedPolicyDocument "Could not parse the
    policy: Statement is empty!" and GetRole then answers NoSuchEntity; a role with a real lambda.amazonaws.com
    trust statement runs a function as its assumed role.
    """
    iam = ctx.client("iam")
    lam = ctx.client("lambda")

    bad_role_name = ctx.unique_name("sim2real-lambda-trust-empty-")
    empty_trust_doc = json.dumps({"Version": "2012-10-17", "Statement": []})

    def _try_create_role():
        iam.create_role(RoleName=bad_role_name, AssumeRolePolicyDocument=empty_trust_doc)

    code_seen, message_seen = _error(_try_create_role)
    assert code_seen == "MalformedPolicyDocument", (code_seen, message_seen)
    assert message_seen == "Could not parse the policy: Statement is empty!", message_seen

    not_found_code, not_found_message = _error(lambda: iam.get_role(RoleName=bad_role_name))
    assert not_found_code == "NoSuchEntity", (not_found_code, not_found_message)
    assert not_found_message == f"The role with name {bad_role_name} cannot be found.", not_found_message

    # positive control: a role with a real trust statement works end to end
    good_role_name = ctx.unique_name("sim2real-lambda-trust-real-")
    good_role_arn = _create_role(ctx, iam, good_role_name, "lambda.amazonaws.com")
    good_func_name = ctx.unique_name("sim2real-lambda-trust-real-fn-")
    _create_function_with_retry(
        lam,
        FunctionName=good_func_name,
        Runtime="python3.12",
        Role=good_role_arn,
        Handler="index.handler",
        Code={"ZipFile": _zip_lambda_code(_HANDLER_STS)},
        Timeout=15,
    )
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=good_func_name))
    _wait_active(lam, good_func_name)
    invoke_resp = lam.invoke(FunctionName=good_func_name, InvocationType="RequestResponse")
    assert invoke_resp["StatusCode"] == 200
    assert "FunctionError" not in invoke_resp
    payload = json.loads(invoke_resp["Payload"].read())
    assert ":assumed-role/" in payload["arn"], payload
    assert f"assumed-role/{good_role_name}/" in payload["arn"], payload


def _trust_policy(principal_service: str) -> str:
    return json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Principal": {"Service": principal_service}, "Action": "sts:AssumeRole"}
            ],
        }
    )


def _create_role(ctx, iam, role_name: str, principal_service: str) -> str:
    resp = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=_trust_policy(principal_service))
    role_arn = resp["Role"]["Arn"]

    def _cleanup():
        try:
            iam.delete_role(RoleName=role_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise

    ctx.on_cleanup(_cleanup)
    return role_arn


def _zip_lambda_code(handler_src: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("index.py", handler_src)
    return buf.getvalue()


def _create_function_with_retry(lam, *, timeout_s: float = 90.0, interval_s: float = 3.0, **kwargs: Any):
    deadline = time.monotonic() + timeout_s
    last_exc: ClientError | None = None
    while time.monotonic() < deadline:
        try:
            return lam.create_function(**kwargs)
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            msg = exc.response["Error"].get("Message", "")
            if code == "InvalidParameterValueException" and "cannot be assumed" in msg:
                last_exc = exc
                time.sleep(interval_s)
                continue
            raise
    assert last_exc is not None
    raise last_exc


def _wait_active(lam, func_name: str, timeout_s: float = 60.0, interval_s: float = 2.0) -> None:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        if lam.get_function(FunctionName=func_name)["Configuration"]["State"] == "Active":
            return
        time.sleep(interval_s)
    raise AssertionError(f"function {func_name} never became Active")


def _error(fn) -> tuple[str, str]:
    """Return (Error.Code, Error.Message) of the refusal fn raises; raise if fn succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected rejection but call succeeded and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
