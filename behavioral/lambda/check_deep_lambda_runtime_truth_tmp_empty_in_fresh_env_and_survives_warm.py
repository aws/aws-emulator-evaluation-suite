"""deep-lambda-runtime-truth-tmp-empty-in-fresh-env-and-survives-warm."""
from __future__ import annotations

import io
import json
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deep-lambda-runtime-truth-tmp-empty-in-fresh-env-and-survives-warm"
GROUP = "execution_environment"
SERVICES = ["lambda"]

# Every environment mints ENV_ID and snapshots /tmp at INIT, before this code has written
# anything. Each invocation then lists /tmp BEFORE appending one byte to its own env's marker.
_PROBE = """\
import os
import uuid

GEN = "__GEN__"
ENV_ID = uuid.uuid4().hex
INIT_TMP = sorted(os.listdir("/tmp"))
SERVED = 0


def handler(event, context):
    global SERVED
    SERVED += 1
    before = sorted(os.listdir("/tmp"))
    marker = "/tmp/sim2real-" + ENV_ID
    with open(marker, "a") as fh:
        fh.write("x")
    return {
        "gen": GEN,
        "env_id": ENV_ID,
        "served": SERVED,
        "init_tmp": INIT_TMP,
        "before": before,
        "marker": os.path.basename(marker),
        "size": os.path.getsize(marker),
    }
"""


_BASIC = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"


def _zip(files):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, body in files.items():
            zf.writestr(name, body)
    return buf.getvalue()


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


def _create_function(ctx, lam, role_arn, name, **kwargs):
    ctx.on_cleanup(lambda: _reap_log_group(ctx, f"/aws/lambda/{name}"))
    deadline = time.monotonic() + 120
    while True:
        try:
            lam.create_function(FunctionName=name, Role=role_arn,
                                Tags={"sim2real": CHECK}, **kwargs)
            break
        except ClientError as exc:
            msg = exc.response["Error"].get("Message", "")
            # IAM propagation exposes no pollable condition; the bounded retry is the fix.
            if "cannot be assumed" in msg and time.monotonic() < deadline:
                time.sleep(3)
                continue
            raise
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=name))
    return _wait_ready(lam, name)


def _invoke(lam, fn):
    resp = lam.invoke(FunctionName=fn, InvocationType="RequestResponse", Payload=b"{}")
    raw = resp["Payload"].read()
    assert not resp.get("FunctionError"), (
        f"{fn} FunctionError={resp.get('FunctionError')!r}: {raw[:400]!r}")
    return json.loads(raw)


def _run_generation(lam, fn, gen, max_invokes=10):
    """Serial invokes until one environment has served at least two; return every body."""
    bodies = []
    for _ in range(max_invokes):
        body = _invoke(lam, fn)
        assert body["gen"] == gen, f"expected code generation {gen!r}, got {body!r}"
        bodies.append(body)
        if body["served"] >= 2 and len(bodies) >= 3:
            break
    return bodies


def _assert_env_invariants(bodies, label):
    by_env = {}
    for b in bodies:
        by_env.setdefault(b["env_id"], []).append(b)
    for env_id, seq in by_env.items():
        assert seq[0]["init_tmp"] == [], (
            f"{label}: environment {env_id} saw a NON-EMPTY /tmp at INIT {seq[0]['init_tmp']!r} "
            f"-- a fresh execution environment must start with an empty /tmp")
        for i, b in enumerate(seq):
            assert b["served"] == i + 1, (
                f"{label}: env {env_id} served-counter sequence broke at {i}: {b!r}")
            want_before = [] if i == 0 else [b["marker"]]
            assert b["before"] == want_before, (
                f"{label}: env {env_id} invocation {i + 1} listed /tmp={b['before']!r}, expected "
                f"{want_before!r} (only its own env's marker, and only after the first write)")
            assert b["size"] == i + 1, (
                f"{label}: env {env_id} marker has {b['size']!r} bytes after {i + 1} appends")
    reused = [e for e, seq in by_env.items() if len(seq) >= 2]
    assert reused, (
        f"{label}: {len(bodies)} serial invocations never reused an environment "
        f"(served counters {[b['served'] for b in bodies]!r}); warm /tmp persistence unobservable")
    return set(by_env)


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """/tmp is empty in each fresh environment and persists across warm invokes; a code update or
    a configuration change retires the environments, so the next generation starts with empty /tmp.

    Reference: https://docs.aws.amazon.com/lambda/latest/dg/lambda-runtime-environment.html
    """
    lam = ctx.client("lambda")
    role_arn = _make_role(ctx)
    fn = ctx.unique_name("sim2real-behav-rt-tmp-")
    _create_function(
        ctx, lam, role_arn, fn, Runtime="python3.12", Handler="index.handler",
        Code={"ZipFile": _zip({"index.py": _PROBE.replace("__GEN__", "g1")})},
        MemorySize=256, Timeout=30,
    )

    # No reserved concurrency (the account quota may leave none to reserve): assertions are
    # invariants over whichever environments served, keyed by an INIT-minted id.
    g1 = _run_generation(lam, fn, "g1")
    envs_g1 = _assert_env_invariants(g1, "g1")

    # ---- break the environment by a CODE update ----
    lam.update_function_code(
        FunctionName=fn, ZipFile=_zip({"index.py": _PROBE.replace("__GEN__", "g2")}))
    _wait_ready(lam, fn)
    g2 = _run_generation(lam, fn, "g2")
    envs_g2 = _assert_env_invariants(g2, "g2")
    assert envs_g2.isdisjoint(envs_g1), (
        f"UpdateFunctionCode must retire every g1 environment; g2 was served by "
        f"{sorted(envs_g2 & envs_g1)!r} which also served g1")
    g1_markers = {b["marker"] for b in g1}
    for b in g2:
        assert not (set(b["before"]) & g1_markers), (
            f"a g2 invocation still listed a g1 /tmp marker: {b['before']!r} -- the code update "
            f"did not give the new generation a fresh /tmp")

    # ---- and again by a CONFIGURATION-only change (same code bytes) ----
    lam.update_function_configuration(FunctionName=fn, MemorySize=384)
    cfg = _wait_ready(lam, fn)
    assert cfg["MemorySize"] == 384, f"MemorySize update did not land: {cfg['MemorySize']!r}"
    g3 = _run_generation(lam, fn, "g2")
    envs_g3 = _assert_env_invariants(g3, "g2-after-config")
    assert envs_g3.isdisjoint(envs_g1 | envs_g2), (
        f"a configuration change must retire the serving environments; "
        f"{sorted(envs_g3 & (envs_g1 | envs_g2))!r} survived it")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
