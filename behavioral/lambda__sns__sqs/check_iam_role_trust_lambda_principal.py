"""iam-role-trust-lambda-principal."""
from __future__ import annotations

import io
import json
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "iam-role-trust-lambda-principal"
GROUP = "iam-trust"
SERVICES = ["lambda", "sns", "sqs"]


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A role trusting lambda.amazonaws.com backs a function that Lambda runs: Invoke returns status
    200, no FunctionError and the value computed inside the function."""
    iam = ctx.client("iam")
    lam = ctx.client("lambda")

    _role_name, role_arn = _create_role(
        ctx,
        iam,
        trust_principals=["lambda.amazonaws.com"],
        managed_policy_arns=["arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"],
    )

    func_name = ctx.unique_name("sim2real-iamtrust-fn-")
    code = _lambda_zip_bytes(
        "def handler(event, context):\n"
        "    return {'echo': event}\n"
    )
    _create_function_with_retry(
        lam,
        FunctionName=func_name,
        Runtime="python3.12",
        Role=role_arn,
        Handler="index.handler",
        Code={"ZipFile": code},
        Timeout=15,
        Tags=_resource_tags(),
    )
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=func_name))
    _wait_for_function_active(lam, func_name)

    invoke = lam.invoke(FunctionName=func_name, Payload=json.dumps({"k": "v"}).encode())
    assert invoke["StatusCode"] == 200, f"expected StatusCode 200, got {invoke['StatusCode']}"
    assert invoke.get("FunctionError") is None, (
        f"expected no FunctionError, got {invoke.get('FunctionError')}"
    )
    payload = json.loads(invoke["Payload"].read())
    expected = {"echo": {"k": "v"}}
    assert payload == expected, f"expected {expected}, got {payload}"


def _resource_tags() -> dict[str, str]:
    return {"sim2real:managed": "true", "sim2real:prefix": "sim2real-iamtrust"}


def _resource_tags_kv() -> list[dict[str, str]]:
    return [{"Key": k, "Value": v} for k, v in _resource_tags().items()]


def _create_role(ctx, iam, trust_principals, managed_policy_arns=None, inline_policy=None):
    role_name = ctx.unique_name("sim2real-iamtrust-role-")
    trust_doc = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": p}, "Action": "sts:AssumeRole"}
            for p in trust_principals
        ],
    }
    resp = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_doc),
        Tags=_resource_tags_kv(),
    )
    role_arn = resp["Role"]["Arn"]
    attached: list[str] = []
    for policy_arn in managed_policy_arns or []:
        iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
        attached.append(policy_arn)
    inline_name = None
    if inline_policy:
        inline_name = f"{role_name}-inline"
        iam.put_role_policy(
            RoleName=role_name, PolicyName=inline_name, PolicyDocument=json.dumps(inline_policy)
        )

    def _cleanup():
        if inline_name:
            try:
                iam.delete_role_policy(RoleName=role_name, PolicyName=inline_name)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "NoSuchEntity":
                    raise
        for pa in attached:
            try:
                iam.detach_role_policy(RoleName=role_name, PolicyArn=pa)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "NoSuchEntity":
                    raise
        try:
            iam.delete_role(RoleName=role_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise

    ctx.on_cleanup(_cleanup)
    return role_name, role_arn


def _lambda_zip_bytes(handler_body: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("index.py", handler_body)
    return buf.getvalue()


def _create_function_with_retry(lam, timeout_s: float = 90.0, interval_s: float = 5.0, **kwargs):
    """CreateFunction can transiently fail right after role creation because IAM's
    trust-policy write has not yet propagated everywhere Lambda checks it; retry the
    specific 'cannot be assumed' error until it clears or the bound expires."""
    deadline = time.monotonic() + timeout_s
    last_err: ClientError | None = None
    while time.monotonic() < deadline:
        try:
            return lam.create_function(**kwargs)
        except ClientError as e:
            code = e.response["Error"]["Code"]
            msg = e.response["Error"].get("Message", "")
            if code == "InvalidParameterValueException" and "cannot be assumed" in msg:
                last_err = e
                time.sleep(interval_s)
                continue
            raise
    assert last_err is not None, "retry loop exited without ever calling create_function"
    raise last_err


def _wait_for_function_active(lam, func_name, timeout_s: float = 60.0, interval_s: float = 2.0):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        state = lam.get_function_configuration(FunctionName=func_name)["State"]
        if state == "Active":
            return
        time.sleep(interval_s)
    raise AssertionError(f"function {func_name} never became Active")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
