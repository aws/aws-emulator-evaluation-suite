"""provisioned-concurrency-on-snapstart-version-rejected."""

from __future__ import annotations

import io
import json
import textwrap
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "provisioned-concurrency-on-snapstart-version-rejected"
GROUP = 'concurrency'
SERVICES = ['lambda']

HANDLER = """\
import uuid

INIT_ID = str(uuid.uuid4())


def handler(event, context):
    return {"init_id": INIT_ID, "ok": True}
"""


def _make_zip(code, filename="index.py"):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(filename, textwrap.dedent(code))
    return buf.getvalue()


_ROLES: dict = {}
_BASIC_EXEC = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
_ROLE_NOT_READY = "The role defined for the function cannot be assumed by Lambda."


def _role_arn(ctx):
    """Create this run's own Lambda execution role (once per run) and return its ARN."""
    if id(ctx) in _ROLES:
        return _ROLES[id(ctx)]
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-behav-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    arn = iam.create_role(RoleName=name, AssumeRolePolicyDocument=json.dumps(trust))["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    iam.attach_role_policy(RoleName=name, PolicyArn=_BASIC_EXEC)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=name, PolicyArn=_BASIC_EXEC))
    _ROLES[id(ctx)] = arn
    return arn


def _create_function(lam, **kwargs):
    """CreateFunction, retried while a freshly created execution role is still propagating."""
    deadline = time.monotonic() + 90
    while True:
        try:
            return lam.create_function(**kwargs)
        except ClientError as exc:
            err = exc.response.get("Error", {})
            not_ready = (err.get("Code") == "InvalidParameterValueException"
                         and err.get("Message") == _ROLE_NOT_READY)
            if not not_ready or time.monotonic() > deadline:
                raise
            time.sleep(3)


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


def _poll(probe, timeout_s, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        got = probe()
        if got:
            return got
        time.sleep(interval_s)
    return None


def _wait_active(lam, fn, timeout_s=240):
    def _probe():
        cfg = lam.get_function_configuration(FunctionName=fn)
        if cfg["State"] == "Failed":
            raise AssertionError(f"{fn} entered State=Failed: {cfg.get('StateReason')}")
        if cfg["State"] == "Active" and cfg.get("LastUpdateStatus") in (None, "Successful"):
            return cfg
        return None

    cfg = _poll(_probe, timeout_s)
    assert cfg is not None, f"{fn} did not reach State=Active within {timeout_s}s"
    return cfg


def _error(call):
    """The AWS error (code, message) for a call that MUST fail; an unexpected success raises."""
    try:
        call()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(
        "PutProvisionedConcurrencyConfig was expected to be refused on a SnapStart version but it "
        "SUCCEEDED — the two features are mutually exclusive and a provisioned config now exists"
    )


def _deploy(ctx, lam, snapstart):
    name = ctx.unique_name("sim2real-behav-ssxfn-")
    _create_function(lam, 
        FunctionName=name, Runtime="python3.12", Handler="index.handler",
        Role=_role_arn(ctx), Code={"ZipFile": _make_zip(HANDLER)},
        MemorySize=512, Timeout=30,
        Tags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav-ssxfn-"},
    )
    ctx.on_cleanup(lambda: _cleanup_fn(ctx, lam, name))
    _wait_active(lam, name)
    if snapstart:
        lam.update_function_configuration(
            FunctionName=name, SnapStart={"ApplyOn": "PublishedVersions"}
        )
        cfg = _wait_active(lam, name)
        assert (cfg.get("SnapStart") or {}).get("ApplyOn") == "PublishedVersions", (
            f"SnapStart.ApplyOn did not round-trip on {name}: {cfg.get('SnapStart')!r}"
        )
    version = lam.publish_version(FunctionName=name)["Version"]
    return name, version


def _invoke_ok(lam, target):
    resp = lam.invoke(FunctionName=target, Payload=b"{}")
    raw = resp["Payload"].read()
    assert resp["StatusCode"] == 200, f"{target}: StatusCode {resp['StatusCode']!r} {raw!r}"
    assert "FunctionError" not in resp, (
        f"{target} failed with FunctionError={resp.get('FunctionError')!r}: {raw!r}"
    )
    return json.loads(raw)


@tags("axis:rejection", "cap:c3", "cap:c4", "concern:data-plane", "concern:negative-classes",
      "dp:api", "plane:control", "plane:data")
def run(ctx) -> None:
    """Provisioned concurrency on a SnapStart version is ResourceConflictException with the exact
    message and leaves no config, while the same request on an otherwise identical version without
    SnapStart is accepted IN_PROGRESS or READY."""
    lam = ctx.client("lambda")

    snap_fn, snap_version = _deploy(ctx, lam, snapstart=True)
    plain_fn, plain_version = _deploy(ctx, lam, snapstart=False)

    # The SnapStart version must be a real, usable version before its refusal means anything.
    snap_qualified = f"{snap_fn}:{snap_version}"
    snap_cfg = _poll(
        lambda: (
            lambda c: c if (
                c.get("State") == "Active"
                and (c.get("SnapStart") or {}).get("OptimizationStatus") == "On"
            ) else None
        )(lam.get_function(FunctionName=snap_qualified)["Configuration"]),
        timeout_s=300,
        interval_s=5.0,
    )
    assert snap_cfg is not None, (
        f"{snap_qualified} never reached Active with SnapStart.OptimizationStatus=='On' within "
        f"300s — the negative below would then be refused for the wrong reason"
    )
    assert (snap_cfg.get("SnapStart") or {}).get("OptimizationStatus") == "On", (
        f"the SnapStart version is not optimized: {snap_cfg.get('SnapStart')!r}"
    )

    # ---- break exactly one thing: ask for provisioned concurrency on the SnapStart version ----
    code, msg = _error(
        lambda: lam.put_provisioned_concurrency_config(
            FunctionName=snap_fn, Qualifier=snap_version, ProvisionedConcurrentExecutions=1
        )
    )
    assert code == "ResourceConflictException", (
        f"provisioned concurrency on a SnapStart-enabled version was refused with {code!r}, not "
        f"ResourceConflictException"
    )
    assert msg == (
        "The operation cannot be performed at this time. "
        "Provisioned Concurrency is not supported for SnapStart enabled functions"
    ), f"expected the exact SnapStart-conflict message, got {msg!r}"

    # ---- the effect is absent: no config was created, by either read path ----
    absent, absent_msg = _error(
        lambda: lam.get_provisioned_concurrency_config(FunctionName=snap_fn, Qualifier=snap_version)
    )
    assert absent == "ProvisionedConcurrencyConfigNotFoundException", (
        f"reading back the refused config returned {absent!r} instead of "
        f"ProvisionedConcurrencyConfigNotFoundException — the refusal created a config anyway"
    )
    assert absent_msg == "No Provisioned Concurrency Config found for this function", f"expected the exact config-not-found message, got {absent_msg!r}"
    listed = []
    paginator = lam.get_paginator("list_provisioned_concurrency_configs")
    for page in paginator.paginate(FunctionName=snap_fn):
        listed.extend(page.get("ProvisionedConcurrencyConfigs", []))
    assert listed == [], (
        f"the refused Put left a provisioned-concurrency config on {snap_fn}: {listed!r}"
    )
    # The refused call must also not have damaged the version it named.
    assert _invoke_ok(lam, snap_qualified)["ok"] is True, (
        "the SnapStart version stopped serving invocations after the refused Put"
    )

    # ---- positive control: the identical request on the non-SnapStart twin is accepted ----
    plain_put = lam.put_provisioned_concurrency_config(
        FunctionName=plain_fn, Qualifier=plain_version, ProvisionedConcurrentExecutions=1
    )
    # Registered immediately: a provisioned config bills from the moment it is READY, and this one
    # is deliberately never waited on, so the delete must not depend on reaching READY first.
    ctx.on_cleanup(
        lambda: lam.delete_provisioned_concurrency_config(
            FunctionName=plain_fn, Qualifier=plain_version
        )
    )
    assert plain_put["RequestedProvisionedConcurrentExecutions"] == 1, (
        f"the control's Put did not record the requested concurrency: {plain_put!r}"
    )
    control = lam.get_provisioned_concurrency_config(
        FunctionName=plain_fn, Qualifier=plain_version
    )
    assert control["RequestedProvisionedConcurrentExecutions"] == 1, (
        f"the control's config did not persist: {control!r}"
    )
    assert control["Status"] in ("IN_PROGRESS", "READY"), (
        f"the control's provisioned config reports {control['Status']!r}; it is deliberately not "
        f"waited to READY, but it must be allocating or allocated rather than failed"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
