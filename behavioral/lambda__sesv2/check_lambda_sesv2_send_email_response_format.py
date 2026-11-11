"""lambda-sesv2-send-email-response-format."""

from __future__ import annotations

import io
import json
import re
import textwrap
import time
import zipfile

from behavioral_harness import tags

CHECK = "lambda-sesv2-send-email-response-format"
GROUP = "data-format"
SERVICES = ["lambda", "sesv2"]


@tags(
    "axis:happy-path",
    "cap:c3",
    "concern:data-plane",
    "concern:e2e",
    "concern:representation",
    "dp:api",
    "plane:data",
    "requires:dns-baseline",
)
def run(ctx) -> None:
    """A Lambda handler's sesv2.send_email response, minus ResponseMetadata, matches the
    SendEmailResponse shape exactly: one field, MessageId, a non-empty id-like token."""
    from_addr = _verified_sender(ctx)
    role_arn = _create_lambda_role(ctx, ["ses:SendEmail"])
    fn_name = _create_sesv2_lambda(ctx, role_arn)

    payload = _invoke(
        ctx,
        fn_name,
        "send_email",
        {
            "FromEmailAddress": from_addr,
            "Destination": {"ToAddresses": ["success@simulator.amazonses.com"]},
            "Content": {
                "Simple": {
                    "Subject": {"Data": "sim2real data-format check"},
                    "Body": {"Text": {"Data": "checking response shape"}},
                }
            },
        },
    )

    assert payload["ok"] is True, f"unexpected failure: {payload}"
    result = payload["result"]
    # SendEmailResponse in the SESv2 API model has exactly one member: MessageId.
    assert set(result.keys()) == {"MessageId"}, f"unexpected response shape: {result}"
    message_id = result["MessageId"]
    assert isinstance(message_id, str) and len(message_id) > 10, (
        f"unexpected MessageId value: {message_id!r}"
    )
    assert re.match(r"^[0-9A-Za-z\-]+$", message_id), (
        f"unexpected MessageId format: {message_id!r}"
    )


# ===== helpers =====

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
    import boto3

    def handler(event, context):
        client = boto3.client("sesv2")
        op = event["op"]
        params = event.get("params", {})
        try:
            method = getattr(client, op)
            resp = method(**params)
            resp.pop("ResponseMetadata", None)
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
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=_LAMBDA_TRUST_POLICY,
        Tags=[{"Key": "sim2real", "Value": "true"}],
    )
    role_arn = role["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    policy_name = "sesv2-inline"
    policy_doc = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Action": inline_actions, "Resource": "*"}
            ],
        }
    )
    iam.put_role_policy(
        RoleName=role_name, PolicyName=policy_name, PolicyDocument=policy_doc
    )
    ctx.on_cleanup(
        lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name)
    )

    basic_exec_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=basic_exec_arn)
    ctx.on_cleanup(
        lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=basic_exec_arn)
    )
    return role_arn


def _create_sesv2_lambda(ctx, role_arn: str) -> str:
    lam = ctx.client("lambda")
    fn_name = ctx.unique_name("sim2real-sesv2-fn-")
    zip_bytes = _build_zip(_HANDLER_SOURCE)

    deadline = time.monotonic() + 45
    last_exc = None
    while time.monotonic() < deadline:
        try:
            lam.create_function(
                FunctionName=fn_name,
                Runtime="python3.12",
                Role=role_arn,
                Handler="index.handler",
                Code={"ZipFile": zip_bytes},
                Timeout=30,
                Tags={"sim2real": "true"},
            )
            break
        except lam.exceptions.InvalidParameterValueException as exc:
            last_exc = exc
            time.sleep(3)
    else:
        raise AssertionError(
            f"lambda function never became creatable (role propagation): {last_exc}"
        )

    ctx.on_cleanup(lambda: _delete_function_log_group(ctx, fn_name))
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=fn_name))
    lam.get_waiter("function_active_v2").wait(FunctionName=fn_name, WaiterConfig={"Delay": 2, "MaxAttempts": 150})
    return fn_name


def _invoke(ctx, fn_name: str, op: str, params: dict) -> dict:
    lam = ctx.client("lambda")
    resp = lam.invoke(
        FunctionName=fn_name,
        Payload=json.dumps({"op": op, "params": params}).encode("utf-8"),
    )
    raw = resp["Payload"].read()
    assert resp.get("FunctionError") is None, (
        f"lambda invocation errored: {resp.get('FunctionError')} {raw!r}"
    )
    return json.loads(raw)


def _verified_sender(ctx) -> str:
    """Return a From-address SES will accept for sending.

    SES identity verification requires an out-of-band step (DNS record or a clicked email link) that
    cannot be automated in this check, so this looks for an identity the account already has
    verified -- the same prerequisite every other send-email check in this directory relies on.
    """
    sesv2 = ctx.client("sesv2")
    next_token = None
    while True:
        kwargs = {"NextToken": next_token} if next_token else {}
        resp = sesv2.list_email_identities(**kwargs)
        for identity in resp.get("EmailIdentities", []):
            if identity.get("VerificationStatus") == "SUCCESS" and identity.get(
                "SendingEnabled", True
            ):
                name = identity["IdentityName"]
                if identity.get("IdentityType") == "DOMAIN":
                    return f"sim2real-check@{name}"
                return name
        next_token = resp.get("NextToken")
        if not next_token:
            break
    raise AssertionError(
        "no verified SES sending identity exists in this account; SES requires a "
        "verified FROM identity to send email"
    )


def _delete_function_log_group(ctx, function_name: str) -> None:
    """Delete the log group Lambda creates for a function on its first invocation and never
    deletes. Registered before the function's own teardown, so it runs after the function is
    gone; the service can still create the group from logs it delivers a few seconds later, so
    the group must stay absent across two consecutive reads 2 s apart. Only an already-absent group is
    tolerated; a group still present after 30 s raises."""
    import time

    from botocore.exceptions import ClientError

    logs = ctx.client("logs")
    group = f"/aws/lambda/{function_name}"

    def present() -> bool:
        found = logs.describe_log_groups(logGroupNamePrefix=group)["logGroups"]
        return any(g["logGroupName"] == group for g in found)

    deadline = time.monotonic() + 30.0
    absent = 0
    while True:
        if absent == 0:
            try:
                logs.delete_log_group(logGroupName=group)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                    raise
        time.sleep(2.0)
        absent = 0 if present() else absent + 1
        if absent == 2:
            return
        if time.monotonic() >= deadline:
            raise RuntimeError(f"log group {group} still present 30 s after delete_log_group")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
