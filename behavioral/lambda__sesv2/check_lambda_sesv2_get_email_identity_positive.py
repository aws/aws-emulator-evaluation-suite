"""lambda-sesv2-get-email-identity-positive."""
from __future__ import annotations

import io
import json
import textwrap
import time
import zipfile

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "lambda-sesv2-get-email-identity-positive"
GROUP = "sdk-invocation"
SERVICES = ["lambda", "sesv2"]


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """A Lambda's GetEmailIdentity on a domain identity created outside the function returns its
    current state: type DOMAIN, not verified for sending, DKIM signing enabled with status
    PENDING and 3 tokens."""
    sesv2 = ctx.client("sesv2")
    domain = f"{ctx.unique_name('sim2real-sesv2-domain')}.example.com"
    sesv2.create_email_identity(EmailIdentity=domain)
    ctx.on_cleanup(lambda: sesv2.delete_email_identity(EmailIdentity=domain))

    role_arn = _create_lambda_role(ctx, ["ses:GetEmailIdentity"])
    fn_name = _create_sesv2_lambda(ctx, role_arn)

    payload = _invoke(ctx, fn_name, "get_email_identity", {"EmailIdentity": domain})

    assert payload["ok"] is True, f"unexpected failure: {payload}"
    result = payload["result"]
    assert result["IdentityType"] == "DOMAIN", f"expected IdentityType=DOMAIN, got {result.get('IdentityType')!r}"
    # We never completed the (unautomatable) out-of-band domain verification,
    # so the identity's real server-side state must still show unverified.
    assert result["VerifiedForSendingStatus"] is False, (
        f"expected VerifiedForSendingStatus=False for a never-verified domain, got {result.get('VerifiedForSendingStatus')!r}"
    )
    dkim = result.get("DkimAttributes")
    assert dkim is not None, f"expected DkimAttributes to be present, got {result!r}"
    assert dkim.get("SigningEnabled") is True, f"expected DkimAttributes.SigningEnabled=True, got {dkim!r}"
    assert dkim.get("Status") == "PENDING", f"expected DkimAttributes.Status=PENDING for a never-verified domain, got {dkim!r}"
    tokens = dkim.get("Tokens")
    assert isinstance(tokens, list) and len(tokens) == 3, f"expected 3 DKIM CNAME tokens, got {tokens!r}"


_LAMBDA_TRUST_POLICY = json.dumps(
    {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "lambda.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
)

_HANDLER_SOURCE = textwrap.dedent(
    """
    import json

    import boto3

    def handler(event, context):
        client = boto3.client("sesv2")
        op = event["op"]
        params = event.get("params", {})
        try:
            method = getattr(client, op)
            resp = method(**params)
            resp.pop("ResponseMetadata", None)
            # Some fields (e.g. DkimAttributes.LastKeyGenerationTimestamp) are
            # datetimes, which the Lambda runtime's JSON marshaling cannot
            # serialize directly.
            resp = json.loads(json.dumps(resp, default=str))
            return {"ok": True, "result": resp}
        except Exception as exc:  # noqa: BLE001
            resp_meta = getattr(exc, "response", None) or {}
            code = resp_meta.get("Error", {}).get("Code")
            return {"ok": False, "error_code": code, "error_message": str(exc)}
    """
)


def _build_zip(source: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("index.py", source)
    return buf.getvalue()


def _create_lambda_role(ctx, inline_actions: list[str]) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-sesv2-role-")
    role = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=_LAMBDA_TRUST_POLICY)
    role_arn = role["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    policy_name = "sesv2-inline"
    policy_doc = json.dumps(
        {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": inline_actions, "Resource": "*"}]}
    )
    iam.put_role_policy(RoleName=role_name, PolicyName=policy_name, PolicyDocument=policy_doc)
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))

    basic_exec_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=basic_exec_arn)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=basic_exec_arn))
    return role_arn


def _create_sesv2_lambda(ctx, role_arn: str) -> str:
    lam = ctx.client("lambda")
    fn_name = ctx.unique_name("sim2real-sesv2-fn-")
    zip_bytes = _build_zip(_HANDLER_SOURCE)

    deadline = time.monotonic() + 45
    last_exc = None
    while time.monotonic() < deadline:
        try:
            ctx.on_cleanup(lambda _n=fn_name: _delete_lambda_log_group(ctx, _n))
            lam.create_function(
                FunctionName=fn_name,
                Runtime="python3.12",
                Role=role_arn,
                Handler="index.handler",
                Code={"ZipFile": zip_bytes},
                Timeout=30,
            )
            break
        except lam.exceptions.InvalidParameterValueException as exc:
            last_exc = exc
            time.sleep(3)
    else:
        raise AssertionError(f"lambda function never became creatable (role propagation): {last_exc}")

    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=fn_name))
    lam.get_waiter("function_active_v2").wait(FunctionName=fn_name, WaiterConfig={"Delay": 2, "MaxAttempts": 150})
    return fn_name


def _invoke(ctx, fn_name: str, op: str, params: dict) -> dict:
    lam = ctx.client("lambda")
    resp = lam.invoke(FunctionName=fn_name, Payload=json.dumps({"op": op, "params": params}).encode("utf-8"))
    raw = resp["Payload"].read()
    assert resp.get("FunctionError") is None, f"lambda invocation errored: {resp.get('FunctionError')} {raw!r}"
    return json.loads(raw)


def _delete_lambda_log_group(ctx, function_name: str) -> None:
    """Delete the log group Lambda creates on a function's first log line; one never created is fine."""
    try:
        ctx.client("logs").delete_log_group(logGroupName=f"/aws/lambda/{function_name}")
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
