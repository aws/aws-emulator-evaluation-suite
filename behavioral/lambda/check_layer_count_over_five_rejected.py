"""layer-count-over-five-rejected."""

from __future__ import annotations

import io
import json
import textwrap
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "layer-count-over-five-rejected"
GROUP = 'layers'
SERVICES = ['lambda']

# Lambda quota: a function may reference at most 5 layers.
MAX_LAYERS = 5

HANDLER = """\
def handler(event, context):
    values = {}
    for i in range(5):
        mod = __import__("sim2real_layer_%d" % i)
        values["sim2real_layer_%d" % i] = mod.VALUE
    return values
"""


def _make_zip(entries):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, body in entries.items():
            zf.writestr(name, textwrap.dedent(body))
    return buf.getvalue()


_EXEC_ROLES = {}


def _exec_role_arn(ctx):
    """An execution role this check creates, shared by every function it deploys."""
    cached = _EXEC_ROLES.get(id(ctx))
    if cached is not None and cached[0] is ctx:
        return cached[1]
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn))
    _EXEC_ROLES[id(ctx)] = (ctx, arn)
    return arn


def _create_function(lam, kwargs, timeout_s=90):
    """CreateFunction, retried while a freshly created role is not yet assumable by Lambda."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return lam.create_function(**kwargs)
        except ClientError as exc:
            err = exc.response.get("Error", {})
            propagating = (
                err.get("Code") == "InvalidParameterValueException"
                and "cannot be assumed by Lambda" in err.get("Message", "")
            )
            if not propagating or time.monotonic() >= deadline:
                raise
            time.sleep(3.0)


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


def _wait_active(lam, fn, timeout_s=120):
    def _probe():
        cfg = lam.get_function_configuration(FunctionName=fn)
        if cfg["State"] == "Failed":
            raise AssertionError(f"{fn} entered State=Failed: {cfg.get('StateReason')}")
        return cfg if cfg["State"] == "Active" else None

    cfg = _poll(_probe, timeout_s)
    assert cfg is not None, f"{fn} did not reach State=Active within {timeout_s}s"
    return cfg


def _error(call):
    """Call call(); return its (code, message). An unexpected success raises."""
    try:
        result = call()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message") or ""
    raise AssertionError(f"expected a rejection, but the call succeeded and returned {result!r}")


def _publish_layer(ctx, lam, index):
    name = ctx.unique_name("sim2real-behav-layer-")
    zip_bytes = _make_zip(
        {f"python/sim2real_layer_{index}.py": f"VALUE = {index * 11}\n"}
    )
    resp = lam.publish_layer_version(
        LayerName=name,
        Content={"ZipFile": zip_bytes},
        CompatibleRuntimes=["python3.12"],
    )
    arn = resp["LayerVersionArn"]
    ctx.on_cleanup(lambda: lam.delete_layer_version(LayerName=name, VersionNumber=resp["Version"]))
    return arn


@tags("axis:rejection", "cap:c3", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:control", "plane:data")
def run(ctx) -> None:
    """Five layers attach and each is importable at runtime; a sixth is rejected on update and
    create. The refused update leaves the stored layer list unchanged and the function still
    invocable.

    Reference: https://docs.aws.amazon.com/lambda/latest/dg/gettingstarted-limits.html
    """
    lam = ctx.client("lambda")
    layers = [_publish_layer(ctx, lam, i) for i in range(6)]
    five, sixth = layers[:MAX_LAYERS], layers[MAX_LAYERS]

    fn = ctx.unique_name("sim2real-behav-fn-")
    created = _create_function(lam, dict(
        FunctionName=fn, Runtime="python3.12", Handler="index.handler",
        Role=_exec_role_arn(ctx), Code={"ZipFile": _make_zip({"index.py": HANDLER})},
        MemorySize=256, Timeout=30, Layers=five,
        Tags={"sim2real": CHECK},
    ))
    ctx.on_cleanup(lambda: _cleanup_fn(ctx, lam, fn))
    assert [layer["Arn"] for layer in created.get("Layers", [])] == five, created.get("Layers")
    _wait_active(lam, fn)

    resp = lam.invoke(FunctionName=fn, Payload=b"{}")
    assert resp["StatusCode"] == 200, resp["StatusCode"]
    assert "FunctionError" not in resp, resp["Payload"].read()
    body = json.loads(resp["Payload"].read())
    assert body == {f"sim2real_layer_{i}": i * 11 for i in range(MAX_LAYERS)}, (
        f"every one of the {MAX_LAYERS} layers must be importable from /opt/python, got {body}"
    )

    upd_code, upd_msg = _error(
        lambda: lam.update_function_configuration(FunctionName=fn, Layers=five + [sixth])
    )
    assert upd_code == "InvalidParameterValueException", (
        f"expected InvalidParameterValueException attaching a 6th layer (limit {MAX_LAYERS}), got "
        f"{upd_code}: {upd_msg}"
    )
    assert upd_msg == f"Cannot reference more than {MAX_LAYERS} layers.", (
        f"unexpected message attaching a 6th layer on update: {upd_msg!r}"
    )
    stored = [layer["Arn"] for layer in lam.get_function_configuration(FunctionName=fn)["Layers"]]
    assert stored == five, f"the rejected update must not change the layer list, got {stored}"

    resp2 = lam.invoke(FunctionName=fn, Payload=b"{}")
    assert resp2["StatusCode"] == 200 and "FunctionError" not in resp2, resp2.get("FunctionError")

    other = ctx.unique_name("sim2real-behav-fn-")
    ctx.on_cleanup(lambda: _cleanup_fn(ctx, lam, other))
    cr_code, cr_msg = _error(
        lambda: lam.create_function(
            FunctionName=other, Runtime="python3.12", Handler="index.handler",
            Role=_exec_role_arn(ctx), Code={"ZipFile": _make_zip({"index.py": HANDLER})},
            MemorySize=256, Timeout=30, Layers=five + [sixth],
            Tags={"sim2real": CHECK},
        )
    )
    assert cr_code == "InvalidParameterValueException", (
        f"expected InvalidParameterValueException creating with 6 layers, got {cr_code}: {cr_msg}"
    )
    assert cr_msg == f"Cannot reference more than {MAX_LAYERS} layers.", (
        f"unexpected message creating with 6 layers: {cr_msg!r}"
    )
    gone, gone_msg = _error(lambda: lam.get_function(FunctionName=other))
    assert gone == "ResourceNotFoundException", (
        f"the rejected function must not exist, GetFunction returned {gone}"
    )
    expected_gone = f"Function not found: arn:aws:lambda:{ctx.region}:{ctx.account}:function:{other}"
    assert gone_msg == expected_gone, f"expected message {expected_gone!r}, got {gone_msg!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
