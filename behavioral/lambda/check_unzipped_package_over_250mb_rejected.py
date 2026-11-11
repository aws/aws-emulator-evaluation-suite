"""unzipped-package-over-250mb-rejected."""

from __future__ import annotations

import io
import json
import textwrap
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "unzipped-package-over-250mb-rejected"
GROUP = 'packaging'
SERVICES = ['lambda']

# Lambda quota: the deployment package may not exceed 250 MB unzipped.
UNZIPPED_LIMIT = 262144000
OVER_LIMIT_PAD = 270000000
CONTROL_PAD = 8000000

HANDLER = """\
import os


def handler(event, context):
    return {"marker": "sim2real-pkg", "pad_size": os.path.getsize("/var/task/pad.bin")}
"""


_ROLES: dict = {}


def _exec_role_arn(ctx) -> str:
    """An execution role this check creates (once per run) and deletes in cleanup."""
    if id(ctx) in _ROLES:
        return _ROLES[id(ctx)]
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-lambda-exec-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "lambda.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    arn = iam.create_role(RoleName=name, AssumeRolePolicyDocument=json.dumps(trust))["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    policy = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
    iam.attach_role_policy(RoleName=name, PolicyArn=policy)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=name, PolicyArn=policy))
    _ROLES[id(ctx)] = arn
    return arn


def _create_function_when_role_ready(lam, **kwargs):
    """CreateFunction, retried while the role this check just created propagates in IAM."""
    deadline = time.monotonic() + 90
    while True:
        try:
            return lam.create_function(**kwargs)
        except ClientError as exc:
            if "cannot be assumed" in str(exc) and time.monotonic() < deadline:
                time.sleep(3)
                continue
            raise


def _cleanup_fn(ctx, lam, name):
    try:
        lam.delete_function(FunctionName=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise
    try:
        ctx.client("logs").delete_log_group(logGroupName=f"/aws/lambda/{name}")
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _poll(probe, timeout_s, interval_s=1.0):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        got = probe()
        if got:
            return got
        time.sleep(interval_s)
    return None


def _wait_active(lam, fn, timeout_s=180):
    def _probe():
        cfg = lam.get_function_configuration(FunctionName=fn)
        if cfg["State"] == "Failed":
            raise AssertionError(f"{fn} entered State=Failed: {cfg.get('StateReason')}")
        return cfg if cfg["State"] == "Active" else None

    cfg = _poll(_probe, timeout_s)
    assert cfg is not None, f"{fn} did not reach State=Active within {timeout_s}s"
    return cfg


def _error(call):
    """The (code, message) of a call that must fail; an unexpected success raises."""
    try:
        result = call()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message") or ""
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _padded_zip(pad_bytes):
    """A deflate-compressed package: a real handler plus `pad_bytes` of zeros.

    Zeros compress ~1000:1, so a package that is far over the 250 MB *unzipped*
    limit stays far under the 50 MB *zipped* direct-upload limit — which is what
    isolates the unzipped-size gate from the request-size gate.
    """
    buf = io.BytesIO()
    chunk = b"\0" * (4 * 1024 * 1024)
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("index.py", textwrap.dedent(HANDLER))
        with zf.open("pad.bin", "w") as fh:
            written = 0
            while written < pad_bytes:
                n = min(len(chunk), pad_bytes - written)
                fh.write(chunk[:n])
                written += n
    return buf.getvalue()


@tags("axis:rejection", "cap:c3", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:control", "plane:data")
def run(ctx) -> None:
    """A package over 250 MB unzipped is rejected (code, message, and no function left), while the
    same multi-entry deflate package shape under the bound deploys and runs.

    Reference: https://docs.aws.amazon.com/lambda/latest/dg/gettingstarted-limits.html
    """
    lam = ctx.client("lambda")

    over = _padded_zip(OVER_LIMIT_PAD)
    assert len(over) < 50 * 1024 * 1024, (
        f"the over-limit package must stay under the 50 MB zipped upload gate to isolate the "
        f"unzipped gate, got {len(over)} zipped bytes"
    )

    over_name = ctx.unique_name("sim2real-behav-fn-")
    ctx.on_cleanup(lambda: _cleanup_fn(ctx, lam, over_name))
    code, message = _error(
        lambda: _create_function_when_role_ready(lam,
            FunctionName=over_name, Runtime="python3.12", Handler="index.handler",
            Role=_exec_role_arn(ctx), Code={"ZipFile": over}, MemorySize=128, Timeout=30,
            Tags={"sim2real:managed": "true"},
        )
    )
    assert code == "InvalidParameterValueException", (
        f"expected InvalidParameterValueException for a package unzipping to {OVER_LIMIT_PAD} "
        f"bytes (limit {UNZIPPED_LIMIT}), got {code}: {message}"
    )
    assert message == f"Unzipped size must be smaller than {UNZIPPED_LIMIT} bytes", (
        f"the rejection message must name the unzipped-size bound exactly, got {message!r}"
    )

    gone_code, gone_message = _error(lambda: lam.get_function(FunctionName=over_name))
    assert gone_code == "ResourceNotFoundException", (
        f"the rejected function must not exist afterwards, GetFunction returned {gone_code}"
    )
    assert gone_message == (
        f"Function not found: arn:aws:lambda:{ctx.region}:{ctx.account}:function:{over_name}"
    ), (
        f"unexpected GetFunction not-found message, got {gone_message!r}"
    )

    # Control: identical package shape, comfortably under the limit, must deploy and execute.
    ok_name = ctx.unique_name("sim2real-behav-fn-")
    _create_function_when_role_ready(lam,
        FunctionName=ok_name, Runtime="python3.12", Handler="index.handler",
        Role=_exec_role_arn(ctx), Code={"ZipFile": _padded_zip(CONTROL_PAD)},
        MemorySize=128, Timeout=30,
        Tags={"sim2real:managed": "true"},
    )
    ctx.on_cleanup(lambda: _cleanup_fn(ctx, lam, ok_name))
    _wait_active(lam, ok_name)

    resp = lam.invoke(FunctionName=ok_name, Payload=b"{}")
    assert resp["StatusCode"] == 200, resp["StatusCode"]
    assert "FunctionError" not in resp, resp.get("FunctionError")
    body = json.loads(resp["Payload"].read())
    assert body["marker"] == "sim2real-pkg", body
    assert body["pad_size"] == CONTROL_PAD, (
        f"the padded entry must be extracted at full size in the task root, got {body['pad_size']} "
        f"want {CONTROL_PAD}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
