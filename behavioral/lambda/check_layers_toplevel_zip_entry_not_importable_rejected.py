"""layers-toplevel-zip-entry-not-importable-rejected."""

from __future__ import annotations

import io
import json
import time
import uuid
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "layers-toplevel-zip-entry-not-importable-rejected"
GROUP = "layers_runtime"
SERVICES = ["lambda"]

_HANDLER = """\
import os
import sys


def handler(event, context):
    import sim2real_nested as nested

    print("LAYERNEST " + nested.stamp())
    try:
        import sim2real_toplevel

        top = {"imported": True, "token": sim2real_toplevel.TOKEN}
    except Exception as exc:
        top = {"imported": False, "error_type": type(exc).__name__, "error": str(exc)}
    return {
        "nested_token": nested.TOKEN,
        "nested_stamp": nested.stamp(),
        "nested_file": nested.__file__,
        "top": top,
        "opt_entries": sorted(os.listdir("/opt")),
        "opt_syspath": [p for p in sys.path if p == "/opt" or p.startswith("/opt/")],
    }
"""


@tags("axis:rejection", "cap:c3", "concern:data-plane", "concern:negative-classes",
      "dp:api", "plane:data")
def run(ctx) -> None:
    """A layer entry outside python/ is extracted to /opt but fails to import (ModuleNotFoundError),
    while a python/ entry of the same layer imports: /opt/python is on sys.path, /opt is not.
    """
    lam = ctx.client("lambda")
    iam = ctx.client("iam")

    nested_token = uuid.uuid4().hex
    toplevel_token = uuid.uuid4().hex
    assert nested_token != toplevel_token, (
        f"the two module tokens must differ, both were {nested_token!r}"
    )

    role_arn = _create_execution_role(ctx, iam)
    layer_name = ctx.unique_name("sim2real-behav-layers-toplevel-")
    layer_arn = _publish_layer(
        ctx, lam, layer_name,
        {
            "python/sim2real_nested.py": _layer_module(nested_token),
            "sim2real_toplevel.py": _layer_module(toplevel_token),
        },
    )

    fn = ctx.unique_name("sim2real-behav-layers-toplevel-fn-")
    _reap_log_group(ctx, fn)
    _create_function(
        ctx, lam,
        FunctionName=fn,
        Runtime="python3.12",
        Role=role_arn,
        Handler="index.handler",
        Code={"ZipFile": _make_zip({"index.py": _HANDLER})},
        Layers=[layer_arn],
        MemorySize=128,
        Timeout=30,
        Tags={"sim2real": CHECK},
    )
    _wait_active(lam, fn)

    observed = _invoke_json(lam, fn, {})
    nested_stamp = _expected_stamp(nested_token)

    assert observed["nested_stamp"] == nested_stamp, (
        f"the layer's python/sim2real_nested.py must be importable and its stamp() must have run "
        f"(expected {nested_stamp!r}); Invoke returned {observed!r}"
    )
    assert observed["nested_file"] == "/opt/python/sim2real_nested.py", (
        f"the nested module must resolve from /opt/python; __file__ was "
        f"{observed['nested_file']!r}"
    )
    logged = _wait_for_log_line(ctx, fn, f"LAYERNEST {nested_stamp}")
    assert nested_stamp in logged, (
        f"expected the handler's stdout line 'LAYERNEST {nested_stamp}' in /aws/lambda/{fn}; the "
        f"matched event was {logged!r}"
    )

    # The file is extracted, so the refusal below is the import path, not packaging.
    assert "sim2real_toplevel.py" in observed["opt_entries"], (
        f"the layer's top-level entry must still be EXTRACTED to /opt — without that this check "
        f"would be grading packaging rather than the import path; /opt contained "
        f"{observed['opt_entries']!r}"
    )

    top = observed["top"]
    assert top["imported"] is False, (
        f"importing the layer's top-level entry must fail — real AWS puts /opt/python on sys.path, "
        f"never /opt itself; the handler imported it and read TOKEN={top.get('token')!r}"
    )
    assert top["error_type"] == "ModuleNotFoundError", (
        f"the failure must be the Python runtime's own ModuleNotFoundError; the handler reported "
        f"{top!r}"
    )
    assert top["error"] == "No module named 'sim2real_toplevel'", (
        f"the error message must name the module exactly; got {top['error']!r}"
    )
    assert "/opt" not in observed["opt_syspath"], (
        f"/opt itself must NOT be on sys.path; the handler saw {observed['opt_syspath']!r}"
    )
    assert "/opt/python" in observed["opt_syspath"], (
        f"/opt/python must be on sys.path, which is the whole reason the nested module resolved; "
        f"the handler saw {observed['opt_syspath']!r}"
    )


def _layer_module(token: str) -> str:
    """A module whose stamp() no caller can produce without running the layer's own code."""
    return (
        f'TOKEN = "{token}"\n'
        "\n"
        "\n"
        "def stamp():\n"
        '    return TOKEN + ":" + str(len([c for c in TOKEN if c.isdigit()]) % 10)\n'
    )


def _expected_stamp(token: str) -> str:
    return f"{token}:{sum(c.isdigit() for c in token) % 10}"


def _make_zip(files: dict[str, str]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, content in files.items():
            zf.writestr(name, content)
    return buf.getvalue()


def _publish_layer(ctx, lam, layer_name: str, files: dict[str, str]) -> str:
    published = lam.publish_layer_version(
        LayerName=layer_name,
        Content={"ZipFile": _make_zip(files)},
        CompatibleRuntimes=["python3.12"],
        Description=f"sim2real {CHECK}",
    )
    version = published["Version"]
    ctx.on_cleanup(lambda: lam.delete_layer_version(LayerName=layer_name, VersionNumber=version))
    arn = published["LayerVersionArn"]
    assert arn, f"PublishLayerVersion returned no LayerVersionArn for {layer_name!r}: {published!r}"
    return arn


def _create_execution_role(ctx, iam) -> str:
    """This check's own execution role — nothing pre-existing in the account is assumed."""
    role_name = ctx.unique_name("sim2real-behav-layers-role-")
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
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn))
    # IAM propagation is absorbed at first use by the deadline-bound retry in _create_function.
    return role["Role"]["Arn"]


def _create_function(ctx, lam, **kwargs):
    """CreateFunction, retrying only the documented role-propagation refusal; raises on deadline."""
    name = kwargs["FunctionName"]
    ctx.on_cleanup(lambda: _delete_function(lam, name))
    deadline = time.monotonic() + 120.0
    last = None
    while time.monotonic() < deadline:
        try:
            return lam.create_function(**kwargs)
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code not in ("InvalidParameterValueException", "ResourceConflictException"):
                raise
            last = exc
            time.sleep(2)
    raise AssertionError(f"CreateFunction({name}) never succeeded within 120s; last error {last}")


def _delete_function(lam, name: str) -> None:
    lam.delete_function(FunctionName=name)


def _reap_log_group(ctx, fn: str) -> None:
    """Registered before the function exists, so LIFO cleanup runs it after delete_function.

    A buffered stream can flush after the delete and recreate the group, so deletes repeat.
    """
    group = f"/aws/lambda/{fn}"

    def _reap() -> None:
        logs = ctx.client("logs")
        deadline = time.monotonic() + 60.0
        while time.monotonic() < deadline:
            try:
                logs.delete_log_group(logGroupName=group)
            except ClientError as exc:
                if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
                    raise
            time.sleep(5)
            described = logs.describe_log_groups(logGroupNamePrefix=group)["logGroups"]
            if not any(g["logGroupName"] == group for g in described):
                return
        raise RuntimeError(
            f"log group {group} kept reappearing within 60s of repeated deletes"
        )

    ctx.on_cleanup(_reap)


def _invoke_json(lam, fn: str, payload: dict) -> dict:
    resp = lam.invoke(
        FunctionName=fn, InvocationType="RequestResponse", Payload=json.dumps(payload).encode()
    )
    body = resp["Payload"].read().decode()
    assert "FunctionError" not in resp, (
        f"{fn} raised instead of returning a payload for {payload!r}: "
        f"{resp.get('FunctionError')} {body[:400]}"
    )
    assert resp["StatusCode"] == 200, f"Invoke returned StatusCode {resp['StatusCode']}: {body[:400]}"
    return json.loads(body)


def _wait_for_log_line(ctx, fn: str, needle: str, timeout_s: float = 150.0) -> str:
    """Poll the function's own log group for a line the HANDLER printed."""
    logs = ctx.client("logs")
    group = f"/aws/lambda/{fn}"
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            paginator = logs.get_paginator("filter_log_events")
            for page in paginator.paginate(logGroupName=group, filterPattern=f'"{needle}"'):
                for event in page.get("events", []):
                    if needle in event.get("message", ""):
                        return event["message"]
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
                raise
        time.sleep(3)
    raise AssertionError(
        f"the handler's stdout line {needle!r} never appeared in {group} within {timeout_s}s"
    )


def _wait_active(lam, name: str, timeout_s: float = 120.0) -> dict:
    def _probe():
        cfg = lam.get_function_configuration(FunctionName=name)
        if cfg.get("State") == "Failed":
            raise AssertionError(
                f"{name} entered State=Failed: {cfg.get('StateReasonCode')} {cfg.get('StateReason')}"
            )
        return cfg

    return _poll_until(
        _probe, lambda cfg: cfg.get("State") == "Active",
        timeout_s=timeout_s, interval_s=2.0, description=f"{name} reaching State=Active",
    )


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float, description: str):
    """Bounded retry with a deadline. RAISES on timeout, never returns its last value."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not observed within {timeout_s}s; last saw {last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
