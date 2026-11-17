"""parameters-secrets-extension-denies-get-secret-without-the-iam-grant."""
from __future__ import annotations

import io
import json
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "parameters-secrets-extension-denies-get-secret-without-the-iam-grant"
GROUP = "caching"
SERVICES = ["iam", "lambda", "logs", "secretsmanager", "ssm"]

_HANDLER_CODE = """
import json
import urllib.error
import urllib.parse
import urllib.request

import boto3


def handler(event, context):
    secret_id = urllib.parse.quote(event["secretId"], safe="")
    token = boto3.Session().get_credentials().get_frozen_credentials().token
    req = urllib.request.Request(
        f"http://localhost:2773/secretsmanager/get?secretId={secret_id}"
    )
    req.add_header("X-Aws-Parameters-Secrets-Token", token)
    try:
        with urllib.request.urlopen(req) as resp:
            body = json.loads(resp.read())
        return {"ok": True, "secretString": body["SecretString"]}
    except urllib.error.HTTPError as exc:
        return {
            "ok": False,
            "status": exc.code,
            "error_type": exc.headers.get("X-Amzn-Errortype"),
            "body": exc.read().decode(),
        }
"""


def _zip_bytes(code: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("index.py", code)
    return buf.getvalue()


def _teardown(undo, *not_found: str):
    """Run undo(); only the resource's own not-found codes mean it is already gone."""

    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _reap_log_group(logs, name: str, *, reads: int = 3, interval_s: float = 5.0,
                     budget_s: float = 180.0) -> None:
    """Delete log group *name* until *reads* consecutive reads find it absent."""
    deadline = time.monotonic() + budget_s
    absent = 0
    while absent < reads:
        groups = logs.describe_log_groups(logGroupNamePrefix=name)["logGroups"]
        if any(g["logGroupName"] == name for g in groups):
            absent = 0
            try:
                logs.delete_log_group(logGroupName=name)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                    raise
        else:
            absent += 1
        if absent < reads:
            if time.monotonic() > deadline:
                raise AssertionError(
                    f"log group {name!r} still present after {budget_s}s of deletes"
                )
            time.sleep(interval_s)


def _create_function(lam, **kwargs):
    """CreateFunction, retried while a freshly created execution role is still propagating."""
    deadline = time.monotonic() + 90
    while True:
        try:
            return lam.create_function(**kwargs)
        except ClientError as exc:
            err = exc.response.get("Error", {})
            not_ready = (
                err.get("Code") == "InvalidParameterValueException"
                and "cannot be assumed" in (err.get("Message") or "")
            )
            if not not_ready or time.monotonic() > deadline:
                raise
            time.sleep(3)


def _wait_active(lam, name, timeout_s=60):
    deadline = time.monotonic() + timeout_s
    while True:
        got = lam.get_function(FunctionName=name)["Configuration"]
        if got["State"] == "Active":
            return got
        if got["State"] == "Failed" or time.monotonic() >= deadline:
            raise AssertionError(f"function {name!r} never became Active: {got!r}")
        time.sleep(2)


def _invoke(lam, name, payload):
    resp = lam.invoke(FunctionName=name, Payload=json.dumps(payload).encode())
    body = json.loads(resp["Payload"].read())
    assert "FunctionError" not in resp, f"invoke of {name!r} raised inside the function: {body!r}"
    return body


@tags("axis:rejection", "cap:c7", "concern:negative-classes", "concern:data-plane",
      "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """The AWS Parameters and Secrets Lambda Extension's local GetSecretValue proxy denies a
    secret the function's role has no grant for, while a sibling secret it IS granted stays
    readable through the same wiring; granting the missing permission then lets it through.

    Reference: https://docs.aws.amazon.com/secretsmanager/latest/userguide/retrieving-secrets_lambda.html
    """
    sm = ctx.client("secretsmanager")
    iam = ctx.client("iam")
    ssm = ctx.client("ssm")
    lam = ctx.client("lambda")
    logs = ctx.client("logs")

    scenario = "lambda-sm-extension-denied"
    tag_set = [{"Key": "sim2real", "Value": scenario}]

    value_granted = ctx.unique_name("sim2real-behav-ext-granted-")
    name_granted = ctx.unique_name("sim2real-behav-ext-sec-granted-")
    arn_granted = sm.create_secret(
        Name=name_granted, SecretString=value_granted, Tags=tag_set)["ARN"]
    ctx.on_cleanup(_teardown(
        lambda: sm.delete_secret(SecretId=arn_granted, ForceDeleteWithoutRecovery=True),
        "ResourceNotFoundException"))

    value_ungranted = ctx.unique_name("sim2real-behav-ext-ungranted-")
    name_ungranted = ctx.unique_name("sim2real-behav-ext-sec-ungranted-")
    arn_ungranted = sm.create_secret(
        Name=name_ungranted, SecretString=value_ungranted, Tags=tag_set)["ARN"]
    ctx.on_cleanup(_teardown(
        lambda: sm.delete_secret(SecretId=arn_ungranted, ForceDeleteWithoutRecovery=True),
        "ResourceNotFoundException"))

    role_name = ctx.unique_name("sim2real-behav-ext-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"},
                        "Action": "sts:AssumeRole"}],
    }
    role_arn = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust),
                                Tags=[{"Key": "sim2real", "Value": scenario}])["Role"]["Arn"]
    ctx.on_cleanup(_teardown(lambda: iam.delete_role(RoleName=role_name), "NoSuchEntity"))

    def _put_policy(resources):
        iam.put_role_policy(
            RoleName=role_name,
            PolicyName="sim2real-ext-denied",
            PolicyDocument=json.dumps({
                "Version": "2012-10-17",
                "Statement": [
                    {"Effect": "Allow",
                     "Action": ["logs:CreateLogGroup", "logs:CreateLogStream",
                                 "logs:PutLogEvents"],
                     "Resource": "*"},
                    {"Effect": "Allow", "Action": "secretsmanager:GetSecretValue",
                     "Resource": resources},
                ],
            }),
        )

    _put_policy([arn_granted])
    ctx.on_cleanup(_teardown(
        lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="sim2real-ext-denied"),
        "NoSuchEntity"))

    layer_arn = ssm.get_parameter(
        Name="/aws/service/aws-parameters-and-secrets-lambda-extension/x86/latest"
    )["Parameter"]["Value"]

    fn_name = ctx.unique_name("sim2real-behav-ext-fn-")
    ctx.on_cleanup(lambda: _reap_log_group(logs, f"/aws/lambda/{fn_name}"))
    _create_function(
        lam,
        FunctionName=fn_name,
        Runtime="python3.13",
        Role=role_arn,
        Handler="index.handler",
        Code={"ZipFile": _zip_bytes(_HANDLER_CODE)},
        Layers=[layer_arn],
        Timeout=15,
        Tags={"sim2real": scenario},
    )
    ctx.on_cleanup(_teardown(lambda: lam.delete_function(FunctionName=fn_name),
                             "ResourceNotFoundException"))
    _wait_active(lam, fn_name)

    # Positive control: the sibling secret the role IS granted stays reachable through the
    # identical function and wiring.
    control = _invoke(lam, fn_name, {"secretId": arn_granted})
    assert control["ok"] is True, f"the granted secret must be reachable, got {control!r}"
    assert control["secretString"] == value_granted, (
        f"the granted secret must serve its own plaintext {value_granted!r}, got "
        f"{control['secretString']!r}"
    )

    denied = _invoke(lam, fn_name, {"secretId": arn_ungranted})
    assert denied["ok"] is False, (
        f"a secret the role has no grant for must be denied, but the extension returned "
        f"{denied!r}"
    )
    assert denied["status"] == 400, (
        f"the extension's local proxy must answer the ungranted secret with HTTP 400, got "
        f"{denied['status']!r}: {denied!r}"
    )
    assert denied["error_type"] == "AccessDeniedException", (
        f"the proxy's X-Amzn-Errortype header must name Secrets Manager's own "
        f"AccessDeniedException, got {denied['error_type']!r}"
    )
    assert denied["body"] == "an unexpected error occurred while executing request", (
        f"the proxy's denial body must be its fixed text, got {denied['body']!r}"
    )

    # Restore: grant the missing permission on the SAME policy and retry through IAM
    # propagation, which exposes no condition to poll.
    _put_policy([arn_granted, arn_ungranted])
    deadline = time.monotonic() + 60
    granted = None
    while time.monotonic() < deadline:
        granted = _invoke(lam, fn_name, {"secretId": arn_ungranted})
        if granted["ok"] is True:
            break
        time.sleep(3)
    assert granted is not None and granted["ok"] is True, (
        f"after widening the grant to include {arn_ungranted!r}, the identical call must "
        f"succeed; the last attempt still returned {granted!r}"
    )
    assert granted["secretString"] == value_ungranted, (
        f"once granted, the secret must serve its own plaintext {value_ungranted!r}, got "
        f"{granted['secretString']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
