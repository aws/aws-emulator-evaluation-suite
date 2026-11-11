"""env-vars-exactly-4kb-accepted-one-byte-over-rejected-at-create."""

from __future__ import annotations

import io
import json
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "env-vars-exactly-4kb-accepted-one-byte-over-rejected-at-create"
GROUP = "packaging"
SERVICES = ["lambda"]

_LIMIT = 4096

_HANDLER = """\
import os


def handler(event, context):
    return {k: os.environ[k] for k in sorted(os.environ) if k.startswith("SIM2REAL_")}
"""


def _variables(total: int) -> dict[str, str]:
    """Two variables whose compact JSON serialization is exactly ``total`` bytes."""
    variables = {"SIM2REAL_A": "", "SIM2REAL_MARK": "mark"}
    base = len(json.dumps(variables, separators=(",", ":")))
    variables["SIM2REAL_A"] = "a" * (total - base)
    assert len(json.dumps(variables, separators=(",", ":"))) == total
    return variables


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:data-plane", "dp:api", "plane:control", "plane:data")
def run(ctx) -> None:
    """The 4 KB environment budget is measured on the variables' compact JSON and is inclusive: 4096
    bytes create a function whose guest sees every byte, and 4097 are refused with
    InvalidParameterValueException quoting the measured size, creating nothing.

    Reference: https://docs.aws.amazon.com/lambda/latest/dg/configuration-envvars.html
    """
    lam = ctx.client("lambda")
    iam = ctx.client("iam")
    role_arn = _create_execution_role(ctx, iam)
    package = _zip({"index.py": _HANDLER})

    over_vars = _variables(_LIMIT + 1)
    refused = ctx.unique_name("sim2real-behav-l8-env4097-")
    ctx.on_cleanup(
        _teardown(lambda: lam.delete_function(FunctionName=refused), "ResourceNotFoundException")
    )
    code, msg = _error(lambda: _retry_role(ctx, lambda: lam.create_function(
        FunctionName=refused, Runtime="python3.12", Role=role_arn, Handler="index.handler",
        Code={"ZipFile": package}, Environment={"Variables": over_vars}, Timeout=30,
        MemorySize=128, Tags={"sim2real": CHECK},
    )))
    assert code == "InvalidParameterValueException", f"4097 bytes must be refused; got {code!r} {msg!r}"
    assert msg == (
        "Lambda was unable to configure your environment variables because the environment "
        f"variables you have provided exceeded the 4KB limit. Measured size: {_LIMIT + 1} bytes"
    ), f"the refusal must quote the measured 4097 bytes; got {msg!r}"
    code, msg = _error(lambda: lam.get_function(FunctionName=refused))
    assert code == "ResourceNotFoundException", (
        f"the refused create must leave no function; GetFunction gave {code!r} {msg!r}"
    )

    exact_vars = _variables(_LIMIT)
    accepted = ctx.unique_name("sim2real-behav-l8-env4096-")
    _create_function(
        ctx, lam,
        FunctionName=accepted, Runtime="python3.12", Role=role_arn, Handler="index.handler",
        Code={"ZipFile": package}, Environment={"Variables": exact_vars}, Timeout=30,
        MemorySize=128, Tags={"sim2real": CHECK},
    )
    cfg = lam.get_function_configuration(FunctionName=accepted)
    assert cfg["Environment"]["Variables"] == exact_vars, (
        f"exactly 4096 bytes must be stored verbatim; got {len(json.dumps(cfg['Environment']['Variables']))} bytes"
    )
    seen = _invoke_ok(lam, accepted)
    assert seen == exact_vars, (
        f"the guest must see every byte of the 4096-byte set; it saw "
        f"{ {k: len(v) for k, v in seen.items()}!r}"
    )


# ===== helpers =====

def _make_zip(entries) -> bytes:
    """A zip from ``(name, content, mode)`` triples; ``mode`` carries the S_IF* type bits.

    The mode is written into ``external_attr`` with ``create_system=3`` (Unix), which is the only
    place a zip records file type and permission bits.
    """
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, content, mode in entries:
            info = zipfile.ZipInfo(name, date_time=(2024, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.create_system = 3
            info.external_attr = mode << 16
            data = content.encode() if isinstance(content, str) else content
            zf.writestr(info, data)
    return buf.getvalue()


def _zip(files: dict) -> bytes:
    return _make_zip([(name, content, 0o100644) for name, content in files.items()])


def _error(fn) -> tuple[str, str]:
    """``(code, message)`` of the ClientError ``fn`` raises. An unexpected success raises too."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {str(result)[:400]}")


def _teardown(undo, *not_found: str):
    """A cleanup running ``undo()`` where a failed delete raises; only ``not_found`` means gone."""

    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _create_execution_role(ctx, iam) -> str:
    """This check's own execution role — nothing pre-existing in the account is assumed."""
    role_name = ctx.unique_name("sim2real-behav-l8-role-")
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
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(_teardown(lambda: iam.delete_role(RoleName=role_name), "NoSuchEntity"))
    policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    ctx.on_cleanup(
        _teardown(
            lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn), "NoSuchEntity"
        )
    )
    return role["Role"]["Arn"]


def _reap_log_group(ctx, fn: str) -> None:
    """Registered BEFORE the function exists, so LIFO runs it AFTER delete_function.

    delete_function does not remove /aws/lambda/<fn>, and a stream buffered by an invocation that
    already returned can flush after the delete and RECREATE the group (measured: the group can
    first appear ~8 s after the last log event), so this re-deletes until four consecutive reads
    5 s apart find it absent, and raises when its budget runs out.
    """
    group = f"/aws/lambda/{fn}"

    def _reap() -> None:
        logs = ctx.client("logs")
        deadline = time.monotonic() + 120.0
        absent = 0
        while absent < 4:
            groups = logs.describe_log_groups(logGroupNamePrefix=group)["logGroups"]
            if any(g["logGroupName"] == group for g in groups):
                absent = 0
                try:
                    logs.delete_log_group(logGroupName=group)
                except ClientError as exc:
                    if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                        raise
            else:
                absent += 1
            if absent < 4:
                if time.monotonic() > deadline:
                    raise AssertionError(f"log group {group} still present after 120s of deletes")
                time.sleep(5)

    ctx.on_cleanup(_reap)


def _create_function(ctx, lam, **kwargs) -> dict:
    """CreateFunction, retrying only the documented role-propagation refusal; raises on deadline."""
    name = kwargs["FunctionName"]
    _reap_log_group(ctx, name)
    created = _retry_role(ctx, lambda: lam.create_function(**kwargs))
    ctx.on_cleanup(
        _teardown(lambda: lam.delete_function(FunctionName=name), "ResourceNotFoundException")
    )
    _wait_ready(lam, name)
    return created


def _retry_role(ctx, call):
    """Run call(), retrying only Lambda's role-propagation refusal every 2 s for up to 120 s."""
    left = ctx.time_left()
    deadline = time.monotonic() + (120.0 if left is None else min(120.0, left))
    while True:
        try:
            return call()
        except ClientError as exc:
            err = exc.response.get("Error", {})
            if err.get("Code") != "InvalidParameterValueException" or "role" not in err.get(
                "Message", ""
            ).lower():
                raise
            if time.monotonic() >= deadline:
                raise AssertionError(f"the execution role was not assumable within 120s: {exc}") from exc
        time.sleep(2)


def _publish_layer(ctx, lam, layer_name: str, zip_bytes: bytes, **kwargs) -> dict:
    """PublishLayerVersion with its delete registered at once (DeleteLayerVersion is idempotent)."""
    published = lam.publish_layer_version(
        LayerName=layer_name,
        Content={"ZipFile": zip_bytes},
        Description=f"sim2real {CHECK}",
        **kwargs,
    )
    version = published["Version"]
    ctx.on_cleanup(lambda: lam.delete_layer_version(LayerName=layer_name, VersionNumber=version))
    return published


def _wait_ready(lam, name: str, timeout_s: float = 180.0) -> dict:
    """Poll until State=Active and the last update is Successful; a Failed state raises."""
    deadline = time.monotonic() + timeout_s
    cfg: dict = {}
    while time.monotonic() < deadline:
        cfg = lam.get_function_configuration(FunctionName=name)
        if cfg.get("State") == "Failed" or cfg.get("LastUpdateStatus") == "Failed":
            raise AssertionError(
                f"{name} failed: State={cfg.get('State')!r} {cfg.get('StateReason')!r} "
                f"LastUpdateStatus={cfg.get('LastUpdateStatus')!r} "
                f"{cfg.get('LastUpdateStatusReason')!r}"
            )
        if cfg.get("State") == "Active" and cfg.get("LastUpdateStatus") in (None, "Successful"):
            return cfg
        time.sleep(2)
    raise AssertionError(f"{name} not ready within {timeout_s}s; last saw {cfg.get('State')!r}")


def _invoke(lam, fn: str, payload: dict | None = None, qualifier: str | None = None):
    """``(FunctionError or None, parsed payload)`` of one synchronous invocation."""
    kwargs = {"FunctionName": fn, "Payload": json.dumps(payload or {}).encode()}
    if qualifier is not None:
        kwargs["Qualifier"] = qualifier
    resp = lam.invoke(**kwargs)
    assert resp["StatusCode"] == 200, f"Invoke of {fn} returned StatusCode {resp['StatusCode']}"
    body = resp["Payload"].read().decode()
    return resp.get("FunctionError"), json.loads(body)


def _invoke_ok(lam, fn: str, payload: dict | None = None, qualifier: str | None = None):
    error, body = _invoke(lam, fn, payload, qualifier)
    assert error is None, f"{fn} raised ({error}) instead of returning: {str(body)[:600]}"
    return body


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
