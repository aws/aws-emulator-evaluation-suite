"""deep-lambda-runtime-truth-reserved-env-var-at-create-rejected."""
from __future__ import annotations

import io
import json
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deep-lambda-runtime-truth-reserved-env-var-at-create-rejected"
GROUP = "execution_environment"
SERVICES = ["lambda"]

_PROBE = """\
import os


def handler(event, context):
    return {k: os.environ.get(k) for k in
            ("SIM2REAL_USER", "AWS_LAMBDA_LOG_GROUP_NAME", "AWS_LAMBDA_FUNCTION_NAME")}
"""

_SPOOF = "/aws/sim2real/spoofed-group"


# ===== helpers =====
_BASIC = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"


def _zip(files):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, body in files.items():
            zf.writestr(name, body)
    return buf.getvalue()


def _error_code(fn):
    try:
        fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError("the call unexpectedly SUCCEEDED; a ClientError was expected")


def _reap_log_group(ctx, group):
    """delete_function leaves /aws/lambda/<fn>, and a buffered stream can flush after the delete
    and RECREATE it: re-delete until the group stays absent for a 30 s quiet window (bounded)."""
    logs = ctx.client("logs")
    quiet = 0
    for _ in range(16):
        found = logs.describe_log_groups(logGroupNamePrefix=group).get("logGroups", [])
        if any(g["logGroupName"] == group for g in found):
            quiet = 0
            try:
                logs.delete_log_group(logGroupName=group)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                    raise
        else:
            quiet += 1
            if quiet >= 6:
                return
        time.sleep(5)


def _make_role(ctx):
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-behav-rt-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"},
                       "Action": "sts:AssumeRole"}],
    }
    arn = iam.create_role(
        RoleName=name, AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    iam.attach_role_policy(RoleName=name, PolicyArn=_BASIC)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=name, PolicyArn=_BASIC))
    return arn


def _wait_ready(lam, fn, timeout_s=180):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = lam.get_function_configuration(FunctionName=fn)
        if last["State"] == "Failed" or last.get("LastUpdateStatus") == "Failed":
            raise AssertionError(f"{fn} failed: {last.get('StateReason')!r} "
                                 f"{last.get('LastUpdateStatusReason')!r}")
        if last["State"] == "Active" and last.get("LastUpdateStatus") in (None, "Successful"):
            return last
        time.sleep(1.0)
    raise AssertionError(f"{fn} never became Active/Successful in {timeout_s}s; last={last!r}")


def _create_retrying(lam, **kwargs):
    """CreateFunction, retrying only the IAM-propagation refusal (no pollable condition)."""
    deadline = time.monotonic() + 120
    while True:
        try:
            return lam.create_function(**kwargs)
        except ClientError as exc:
            msg = exc.response["Error"].get("Message", "")
            if "cannot be assumed" in msg and time.monotonic() < deadline:
                time.sleep(3)
                continue
            raise


@tags("axis:rejection", "cap:c3", "concern:data-plane", "concern:negative-classes", "dp:api",
      "plane:control", "plane:data")
def run(ctx) -> None:
    """CreateFunction naming a reserved runtime key (AWS_LAMBDA_LOG_GROUP_NAME) in Environment is
    refused with InvalidParameterValueException and creates NOTHING; the same request without that
    one key creates a function whose guest sees the user variable and the GENUINE reserved value."""
    lam = ctx.client("lambda")
    role_arn = _make_role(ctx)
    fn = ctx.unique_name("sim2real-behav-rt-rsv-")
    ctx.on_cleanup(lambda: _reap_log_group(ctx, f"/aws/lambda/{fn}"))
    common = dict(
        FunctionName=fn, Role=role_arn, Runtime="python3.12", Handler="index.handler",
        Code={"ZipFile": _zip({"index.py": _PROBE})}, MemorySize=128, Timeout=15,
        Tags={"sim2real": CHECK},
    )

    # ---- break exactly one thing: one reserved key beside an ordinary one ----
    def _bad_create():
        # If the target wrongly accepts, the function exists: register its delete before raising.
        ctx.on_cleanup(lambda: _delete_quietly(lam, fn))
        return _create_retrying(lam, Environment={"Variables": {
            "SIM2REAL_USER": "kept", "AWS_LAMBDA_LOG_GROUP_NAME": _SPOOF}}, **common)

    code, msg = _error_code(_bad_create)
    assert code == "InvalidParameterValueException", (
        f"CreateFunction with reserved AWS_LAMBDA_LOG_GROUP_NAME returned {code!r} ({msg!r}), "
        f"expected InvalidParameterValueException")
    expected = (
        "Lambda was unable to configure your environment variables because the environment "
        "variables you have provided contains reserved keys that are currently not supported for "
        "modification. Reserved keys used in this request: AWS_LAMBDA_LOG_GROUP_NAME")
    assert msg == expected, f"reserved-key refusal: expected message {expected!r}, got {msg!r}"

    # ---- effect absent: nothing was created ----
    gone, gone_msg = _error_code(lambda: lam.get_function(FunctionName=fn))
    assert gone == "ResourceNotFoundException", (
        f"after the refused create, GetFunction returned {gone!r} ({gone_msg!r}); a refused "
        f"CreateFunction must not leave a function behind")
    expected = f"Function not found: arn:aws:lambda:{ctx.region}:{ctx.account}:function:{fn}"
    assert gone_msg == expected, (
        f"GetFunction after the refused create: expected message {expected!r}, got {gone_msg!r}")

    # ---- positive control: the identical request minus the reserved key ----
    _create_retrying(lam, Environment={"Variables": {"SIM2REAL_USER": "kept"}}, **common)
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=fn))
    cfg = _wait_ready(lam, fn)
    stored = cfg.get("Environment", {}).get("Variables", {})
    assert stored == {"SIM2REAL_USER": "kept"}, f"stored Environment is {stored!r}"
    resp = lam.invoke(FunctionName=fn, Payload=b"{}")
    raw = resp["Payload"].read()
    assert not resp.get("FunctionError"), f"control invoke failed: {raw[:400]!r}"
    seen = json.loads(raw)
    assert seen == {
        "SIM2REAL_USER": "kept",
        "AWS_LAMBDA_LOG_GROUP_NAME": f"/aws/lambda/{fn}",
        "AWS_LAMBDA_FUNCTION_NAME": fn,
    }, f"guest environment is {seen!r}"


def _delete_quietly(lam, fn):
    try:
        lam.delete_function(FunctionName=fn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
