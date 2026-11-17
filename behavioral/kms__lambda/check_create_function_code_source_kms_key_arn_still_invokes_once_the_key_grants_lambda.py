"""create-function-code-source-kms-key-arn-still-invokes-once-the-key-grants-lambda."""
from __future__ import annotations

import json
import time
import zipfile
from io import BytesIO

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-function-code-source-kms-key-arn-still-invokes-once-the-key-grants-lambda"
GROUP = "code-encryption"
SERVICES = ["iam", "kms", "lambda", "logs"]

_PREFIX = "sim2real-xsvc-"
_MANAGED = {"sim2real": "true", "sim2real:prefix": _PREFIX.rstrip("-")}

_TRUST = {
    "Version": "2012-10-17",
    "Statement": [{
        "Effect": "Allow",
        "Principal": {"Service": "lambda.amazonaws.com"},
        "Action": "sts:AssumeRole",
    }],
}

_MARKER_ENV = "MARKER"
_HANDLER = """
import os
def lambda_handler(event, context):
    return {'marker': os.environ['MARKER']}
"""


def _name(ctx, kind: str) -> str:
    return ctx.unique_name(f"{_PREFIX}{kind}-")


def _zip_bytes(source: str) -> bytes:
    buf = BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("index.py", source)
    return buf.getvalue()


def _past_role_propagation(fn, *, timeout_s: float = 90.0):
    """Call fn(), retried on the exact InvalidParameterValueException IAM role propagation produces."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return fn()
        except ClientError as exc:
            err = exc.response.get("Error", {})
            if err.get("Code") != "InvalidParameterValueException" or time.monotonic() > deadline:
                raise
            time.sleep(3)


def _reap_log_group(logs, name: str, *, reads: int = 3, interval_s: float = 5.0,
                     budget_s: float = 180.0) -> None:
    """Delete log group ``name`` until ``reads`` consecutive reads find it absent.

    A buffered log stream can flush and recreate the group after delete_function returns, so one
    delete is not a teardown; raises if it keeps coming back when the budget runs out.
    """
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
                    f"log group {name!r} still present after {budget_s}s of deletes; {absent} clean reads"
                )
            time.sleep(interval_s)


def _wait_terminal_state(lam, fn_name: str, *, timeout_s: float = 90.0) -> str:
    """Poll GetFunctionConfiguration until State leaves Pending; returns the terminal state."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = lam.get_function_configuration(FunctionName=fn_name)["State"]
        if last != "Pending":
            return last
        time.sleep(2)
    raise AssertionError(f"function {fn_name!r} never left Pending; last state {last!r}")


@tags(
    "axis:happy-path",
    "cap:c1",
    "concern:data-plane",
    "dp:api",
    "plane:control",
    "plane:data",
)
def run(ctx) -> None:
    """A deployment package uploaded with Code.SourceKMSKeyArn naming a customer managed key whose
    policy grants the regional Lambda service principal decrypt rights creates normally and still
    invokes correctly, proving the package round-trips through that key."""
    kms = ctx.client("kms")
    iam = ctx.client("iam")
    lam = ctx.client("lambda")
    logs = ctx.client("logs")

    key_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AccountRootFullAccess",
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{ctx.account}:root"},
                "Action": "kms:*",
                "Resource": "*",
            },
            {
                "Sid": "LambdaServiceMayEncryptAndDecryptTheDeploymentPackage",
                "Effect": "Allow",
                "Principal": {"Service": "lambda.amazonaws.com"},
                "Action": ["kms:GenerateDataKey", "kms:Decrypt"],
                "Resource": "*",
            },
        ],
    }
    key = kms.create_key(
        Description=_name(ctx, "codekms-granted-key"),
        Policy=json.dumps(key_policy),
        Tags=[{"TagKey": k, "TagValue": v} for k, v in _MANAGED.items()],
    )["KeyMetadata"]
    key_arn = key["Arn"]
    ctx.on_cleanup(lambda: kms.schedule_key_deletion(KeyId=key_arn, PendingWindowInDays=7))

    role_name = _name(ctx, "codekms-role")
    role_arn = iam.create_role(
        RoleName=role_name,
        Path="/sim2real/",
        AssumeRolePolicyDocument=json.dumps(_TRUST),
        Tags=[{"Key": k, "Value": v} for k, v in _MANAGED.items()],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    fn_name = _name(ctx, "codekms-fn")
    ctx.on_cleanup(lambda: _reap_log_group(logs, f"/aws/lambda/{fn_name}"))
    marker = ctx.unique_name("sim2real-xsvc-codekms-marker-")
    created = _past_role_propagation(lambda: lam.create_function(
        FunctionName=fn_name,
        Runtime="python3.13",
        Role=role_arn,
        Handler="index.lambda_handler",
        Code={"ZipFile": _zip_bytes(_HANDLER), "SourceKMSKeyArn": key_arn},
        Timeout=30,
        Environment={"Variables": {_MARKER_ENV: marker}},
        Tags=_MANAGED,
    ))
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=fn_name))
    assert created["FunctionName"] == fn_name, (
        f"a package encrypted under a correctly granted customer key must still create normally, "
        f"got FunctionName {created.get('FunctionName')!r} expected {fn_name!r}"
    )

    state = _wait_terminal_state(lam, fn_name)
    assert state == "Active", (
        f"a package encrypted under a correctly granted key must settle Active, got {state!r}"
    )
    resp = lam.invoke(FunctionName=fn_name, Payload=b"{}")
    body = json.loads(resp["Payload"].read())
    assert resp.get("StatusCode") == 200 and not resp.get("FunctionError"), (
        f"invoking the KMS-encrypted package must succeed, got StatusCode={resp.get('StatusCode')!r} "
        f"FunctionError={resp.get('FunctionError')!r}: {body!r}"
    )
    assert body == {"marker": marker}, (
        f"the invoked code must be the exact bytes uploaded under the customer key, "
        f"got {body!r} expected marker {marker!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
