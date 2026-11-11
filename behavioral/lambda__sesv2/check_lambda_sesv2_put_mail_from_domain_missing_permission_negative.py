"""lambda-sesv2-put-mail-from-domain-missing-permission-negative."""
from __future__ import annotations

import io
import json
import textwrap
import time
import zipfile

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "lambda-sesv2-put-mail-from-domain-missing-permission-negative"
GROUP = "permission-boundary"
SERVICES = ["lambda", "sesv2"]


@tags("axis:rejection", "cap:c3", "cap:c7", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A Lambda role with ses:PutEmailIdentityMailFromAttributes sets an identity's MAIL FROM
    domain, while a role without it gets AccessDeniedException and leaves that domain unchanged."""
    sesv2 = ctx.client("sesv2")
    domain = f"{ctx.unique_name('sim2real-sesv2-domain')}.example.com"
    sesv2.create_email_identity(EmailIdentity=domain, Tags=[{"Key": "sim2real", "Value": CHECK}])
    ctx.on_cleanup(lambda: sesv2.delete_email_identity(EmailIdentity=domain))

    control_mail_from = f"bounce.{domain}"
    control_role = _create_lambda_role(
        ctx, ["ses:PutEmailIdentityMailFromAttributes", "ses:GetEmailIdentity"]
    )
    control_fn = _create_sesv2_lambda(ctx, control_role)
    control_payload = _invoke(
        ctx,
        control_fn,
        "put_email_identity_mail_from_attributes",
        {
            "EmailIdentity": domain,
            "MailFromDomain": control_mail_from,
            "BehaviorOnMxFailure": "USE_DEFAULT_VALUE",
        },
    )
    assert control_payload["ok"] is True, f"positive control unexpectedly failed: {control_payload}"

    identity_after_control = sesv2.get_email_identity(EmailIdentity=domain)
    actual_after_control = identity_after_control["MailFromAttributes"]["MailFromDomain"]
    assert actual_after_control == control_mail_from, (
        f"positive control should have set MailFromDomain to {control_mail_from!r}, "
        f"an independent GetEmailIdentity read reports {actual_after_control!r}"
    )

    restricted_mail_from = f"bounce2.{domain}"
    restricted_role = _create_lambda_role(ctx, ["ses:GetEmailIdentity"])
    restricted_fn = _create_sesv2_lambda(ctx, restricted_role)
    restricted_payload = _invoke(
        ctx,
        restricted_fn,
        "put_email_identity_mail_from_attributes",
        {
            "EmailIdentity": domain,
            "MailFromDomain": restricted_mail_from,
            "BehaviorOnMxFailure": "USE_DEFAULT_VALUE",
        },
    )
    assert restricted_payload["ok"] is False, f"put should have been denied: {restricted_payload}"
    assert restricted_payload["error_code"] == "AccessDeniedException", (
        f"expected AccessDeniedException for the role missing "
        f"ses:PutEmailIdentityMailFromAttributes, got {restricted_payload['error_code']!r}"
    )

    identity_after_denied = sesv2.get_email_identity(EmailIdentity=domain)
    actual_after_denied = identity_after_denied["MailFromAttributes"]["MailFromDomain"]
    assert actual_after_denied == control_mail_from, (
        f"denied put must have had no effect: expected MailFromDomain to remain "
        f"{control_mail_from!r}, an independent read reports {actual_after_denied!r}"
    )
    assert actual_after_denied != restricted_mail_from, (
        f"denied put must not have applied {restricted_mail_from!r}, but an independent read "
        f"reports MailFromDomain == {actual_after_denied!r}"
    )


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
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
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
                Tags={"sim2real": CHECK},
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
