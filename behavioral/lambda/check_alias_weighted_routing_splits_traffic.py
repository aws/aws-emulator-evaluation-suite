"""alias-weighted-routing-splits-traffic."""

from __future__ import annotations

import io
import json
import textwrap
import time
import zipfile

from behavioral_harness import tags
from botocore.exceptions import ClientError


CHECK = "alias-weighted-routing-splits-traffic"
GROUP = 'versions_aliases'
SERVICES = ['lambda']

# 40 invokes: if routing were pinned to one version the probability of never observing the
# other side is 2**-39, so "both versions seen" is a safe assertion, not a flaky one.
INVOKES = 40
CLEARED_INVOKES = 15
# Clearing RoutingConfig shows in GetAlias immediately, but Invoke routing converges a few
# seconds later, so the invoke side is polled to convergence before the strict assertion.
CLEARED_PROBE = 5
ROUTING_CLEAR_TIMEOUT_S = 60

CODE = """\
def handler(event, context):
    return {"marker": "%s"}
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
    from botocore.exceptions import ClientError

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


def _wait_updated(lam, fn, timeout_s=120):
    def _probe():
        cfg = lam.get_function_configuration(FunctionName=fn)
        status = cfg.get("LastUpdateStatus")
        if status == "Failed":
            raise AssertionError(
                f"{fn} update failed: {cfg.get('LastUpdateStatusReason')}"
            )
        return cfg if status in (None, "Successful") else None

    cfg = _poll(_probe, timeout_s)
    assert cfg is not None, f"{fn} did not settle LastUpdateStatus within {timeout_s}s"
    return cfg


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """A 50/50 weighted alias reaches both versions, and each invoke's ExecutedVersion matches
    the code that ran. Clearing RoutingConfig pins traffic back to the primary version.
    """
    lam = ctx.client("lambda")
    fn = ctx.unique_name("sim2real-behav-fn-")
    _create_function(lam,
        FunctionName=fn, Runtime="python3.12", Handler="index.handler",
        Role=_role_arn(ctx), Code={"ZipFile": _make_zip(CODE % "v1")},
        MemorySize=128, Timeout=30, Publish=False,
        Tags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"},
    )
    ctx.on_cleanup(lambda: _cleanup_fn(ctx, lam, fn))
    _wait_active(lam, fn)

    v1 = lam.publish_version(FunctionName=fn, Description="sim2real-v1")["Version"]
    lam.update_function_code(FunctionName=fn, ZipFile=_make_zip(CODE % "v2"))
    _wait_updated(lam, fn)
    v2 = lam.publish_version(FunctionName=fn, Description="sim2real-v2")["Version"]
    assert v1 != v2, f"PublishVersion must mint distinct versions, got {v1} and {v2}"
    marker_of = {v1: "v1", v2: "v2"}

    alias = "sim2real-canary"
    created = lam.create_alias(
        FunctionName=fn, Name=alias, FunctionVersion=v1,
        RoutingConfig={"AdditionalVersionWeights": {v2: 0.5}},
    )
    assert created["RoutingConfig"]["AdditionalVersionWeights"] == {v2: 0.5}, created

    # Round-trip: the weight must be readable back, not swallowed.
    got = lam.get_alias(FunctionName=fn, Name=alias)
    assert got["FunctionVersion"] == v1, got
    assert got["RoutingConfig"]["AdditionalVersionWeights"] == {v2: 0.5}, (
        f"GetAlias must return the routing weights that were written, got "
        f"{got.get('RoutingConfig')}"
    )

    seen = {}
    for i in range(INVOKES):
        resp = lam.invoke(FunctionName=f"{fn}:{alias}", Payload=b"{}")
        assert resp["StatusCode"] == 200, resp["StatusCode"]
        assert "FunctionError" not in resp, resp["Payload"].read()
        executed = resp.get("ExecutedVersion")
        assert executed in marker_of, (
            f"invoke #{i} of a weighted alias reported ExecutedVersion={executed!r}, which is "
            f"neither of the routed versions {sorted(marker_of)}"
        )
        body = json.loads(resp["Payload"].read())
        assert body["marker"] == marker_of[executed], (
            f"invoke #{i} ran ExecutedVersion={executed} but returned {body} — the reported "
            f"version and the code that actually ran disagree"
        )
        seen[executed] = seen.get(executed, 0) + 1

    assert set(seen) == {v1, v2}, (
        f"a 50/50 weighted alias must reach both versions across {INVOKES} invokes; observed "
        f"{seen} (an emulator that ignores AdditionalVersionWeights pins every invoke to "
        f"FunctionVersion={v1})"
    )

    # Clearing the routing config pins traffic back to the primary version.
    cleared = lam.update_alias(FunctionName=fn, Name=alias, RoutingConfig={})
    assert not (cleared.get("RoutingConfig") or {}).get("AdditionalVersionWeights"), cleared
    # The CONTROL plane is not eventual: GetAlias must already show the weights gone.
    reread = lam.get_alias(FunctionName=fn, Name=alias)
    assert not (reread.get("RoutingConfig") or {}).get("AdditionalVersionWeights"), (
        f"GetAlias still reports routing weights after they were cleared: {reread}"
    )

    # The DATA plane is eventual (see ROUTING_CLEAR_TIMEOUT_S). Poll until a whole sample lands on
    # the primary version; the deadline is the assertion, and the strict per-invoke check follows.
    def _sample_all_primary():
        versions = [
            lam.invoke(FunctionName=f"{fn}:{alias}", Payload=b"{}").get("ExecutedVersion")
            for _ in range(CLEARED_PROBE)
        ]
        return versions if set(versions) == {v1} else None

    assert _poll(_sample_all_primary, ROUTING_CLEAR_TIMEOUT_S, interval_s=2.0) is not None, (
        f"{ROUTING_CLEAR_TIMEOUT_S}s after clearing RoutingConfig, invokes of {fn}:{alias} still "
        f"reached a version other than the primary {v1}; clearing the weights must stop routing "
        f"to {v2}"
    )
    for i in range(CLEARED_INVOKES):
        resp = lam.invoke(FunctionName=f"{fn}:{alias}", Payload=b"{}")
        assert resp.get("ExecutedVersion") == v1, (
            f"after clearing RoutingConfig, invoke #{i} must run {v1}, got "
            f"{resp.get('ExecutedVersion')!r}"
        )
        marker = json.loads(resp["Payload"].read())["marker"]
        assert marker == "v1", (
            f"after clearing RoutingConfig, invoke #{i} ran a version reporting marker "
            f"{marker!r}, expected 'v1'"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
