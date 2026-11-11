"""lambda-secretsmanager-cross-account-secret-denied."""
from __future__ import annotations

import io
import json
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "lambda-secretsmanager-cross-account-secret-denied"
GROUP = "permission-boundary"
SERVICES = ["lambda", "rds", "secretsmanager"]

_HANDLER_SOURCE = """
import boto3
from botocore.exceptions import ClientError


def handler(event, context):
    client = boto3.client("secretsmanager")
    try:
        resp = client.get_secret_value(SecretId=event["secret_id"])
        return {"ok": True, "secret_string": resp["SecretString"]}
    except ClientError as e:
        return {"ok": False, "error_code": e.response["Error"]["Code"], "error_message": e.response["Error"].get("Message")}
"""


@tags("axis:rejection", "cap:c3", "cap:c7", "concern:data-plane", "concern:e2e", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A resource-policy Deny for all but an external role ARN denies a same-account Lambda role
    GetSecretValue despite an identity Allow; an unrestricted control secret reads, and removing
    the resource policy restores the denied call.

    Reference: https://docs.aws.amazon.com/secretsmanager/latest/userguide/auth-and-access_examples_cross.html
    """
    sm = ctx.client("secretsmanager")
    _RES_TAGS = [{"Key": "sim2real", "Value": CHECK}]

    denied_name = ctx.unique_name("sim2real-behav-secret-denied-")
    denied_value = "denied-" + denied_name
    denied_secret = sm.create_secret(Name=denied_name, SecretString=denied_value, Tags=_RES_TAGS)
    denied_arn = denied_secret["ARN"]
    ctx.on_cleanup(lambda: sm.delete_secret(SecretId=denied_arn, ForceDeleteWithoutRecovery=True))

    control_name = ctx.unique_name("sim2real-behav-secret-control-")
    control_value = "control-" + control_name
    control_secret = sm.create_secret(Name=control_name, SecretString=control_value, Tags=_RES_TAGS)
    control_arn = control_secret["ARN"]
    ctx.on_cleanup(lambda: sm.delete_secret(SecretId=control_arn, ForceDeleteWithoutRecovery=True))

    # Explicit Deny on the "denied" secret's resource policy for anyone other than a
    # fixed external-account role ARN (the boundary under test); no such restriction
    # is placed on the control secret.
    resource_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Deny",
                "Principal": "*",
                "Action": "secretsmanager:GetSecretValue",
                "Resource": "*",
                "Condition": {
                    "StringNotEquals": {
                        "aws:PrincipalArn": "arn:aws:iam::111122223333:role/TrustedExternalRole"
                    }
                },
            }
        ],
    }
    sm.put_resource_policy(SecretId=denied_arn, ResourcePolicy=json.dumps(resource_policy))

    # Broad identity-policy Allow so the denial provably comes from the resource
    # policy, not from a missing identity grant.
    identity_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "secretsmanager:GetSecretValue",
                "Resource": "*",
            }
        ],
    }
    role_arn = _create_lambda_role(ctx, identity_policy)
    func = _create_lambda(ctx, role_arn, _HANDLER_SOURCE)

    denied_body = _invoke_json(ctx, func["name"], {"secret_id": denied_arn})
    assert denied_body.get("ok") is False, denied_body
    assert denied_body["error_code"] == "AccessDeniedException", denied_body
    caller_arn = f"arn:aws:sts::{ctx.account}:assumed-role/{role_arn.split('/')[-1]}/{func['name']}"
    assert denied_body["error_message"] == (
        f"User: {caller_arn} is not authorized to perform: secretsmanager:GetSecretValue on "
        f"resource: {denied_arn} with an explicit deny in a resource-based policy"
    ), denied_body
    assert "secret_string" not in denied_body

    control_body = _invoke_until_ok(ctx, func["name"], {"secret_id": control_arn})
    assert control_body.get("ok") is True, control_body
    assert control_body["secret_string"] == control_value

    # Restore: removing the resource policy from the denied secret restores the
    # IDENTICAL call to success, proving the denial was caused by the resource
    # policy and is not a permanent property of the secret or the role.
    sm.delete_resource_policy(SecretId=denied_arn)
    restored_body = _invoke_until_ok(ctx, func["name"], {"secret_id": denied_arn})
    assert restored_body.get("ok") is True, restored_body
    assert restored_body["secret_string"] == denied_value


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


def _create_lambda_role(ctx, policy_document):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-role-")
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=_LAMBDA_TRUST_POLICY,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    role_arn = role["Role"]["Arn"]
    policy_name = f"{role_name}-policy"
    iam.put_role_policy(
        RoleName=role_name, PolicyName=policy_name, PolicyDocument=json.dumps(policy_document)
    )

    def _cleanup():
        try:
            iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
        try:
            iam.delete_role(RoleName=role_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise

    ctx.on_cleanup(_cleanup)
    return role_arn


def _zip_code(source: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("index.py", source)
    return buf.getvalue()


def _wait_function_active(ctx, name, timeout_s=60.0):
    lam = ctx.client("lambda")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        state = lam.get_function(FunctionName=name)["Configuration"]["State"]
        if state == "Active":
            return
        time.sleep(2)
    raise AssertionError(f"function {name} never became Active")


def _create_lambda(ctx, role_arn, source, timeout=30):
    lam = ctx.client("lambda")
    name = ctx.unique_name("sim2real-behav-fn-")
    zip_bytes = _zip_code(source)
    deadline = time.monotonic() + 90.0
    resp = None
    while resp is None:
        try:
            resp = lam.create_function(
                FunctionName=name,
                Runtime="python3.12",
                Role=role_arn,
                Handler="index.handler",
                Code={"ZipFile": zip_bytes},
                Timeout=timeout,
                Tags={"sim2real": CHECK},
            )
        except ClientError as e:
            code = e.response["Error"]["Code"]
            msg = e.response["Error"].get("Message", "")
            if code == "InvalidParameterValueException" and "cannot be assumed" in msg and time.monotonic() < deadline:
                time.sleep(3)
                continue
            raise
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=name))
    _wait_function_active(ctx, name)
    return {"name": name, "arn": resp["FunctionArn"]}


def _invoke_json(ctx, function_name, payload):
    lam = ctx.client("lambda")
    resp = lam.invoke(
        FunctionName=function_name,
        Payload=json.dumps(payload).encode("utf-8"),
        InvocationType="RequestResponse",
    )
    body_raw = resp["Payload"].read()
    if resp.get("FunctionError"):
        raise AssertionError(f"lambda invocation error: {body_raw!r}")
    return json.loads(body_raw)


def _invoke_until_ok(ctx, function_name, payload, timeout_s=30.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    body = None
    while time.monotonic() < deadline:
        body = _invoke_json(ctx, function_name, payload)
        if body.get("ok"):
            return body
        time.sleep(interval_s)
    return body


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
