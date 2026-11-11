"""environment-identity-warm-reuse-and-config-update-forces-cold."""

from __future__ import annotations

import io
import json
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "environment-identity-warm-reuse-and-config-update-forces-cold"
GROUP = 'cold_start'
SERVICES = ['lambda']

# Module scope runs once per execution environment; the check asserts the relationships among
# env_id, log_stream, init_epoch and the two counters, never a single field.
ENV_PROBE = """\
import json
import os
import time
import uuid

ENV_ID = str(uuid.uuid4())
INIT_PID = os.getpid()
INIT_EPOCH = time.time()
INIT_COUNT = 0
INIT_COUNT += 1          # must be 1 forever, in every environment, on every invoke
INVOKE_COUNT = 0         # increments once per invocation served BY THIS environment


def handler(event, context):
    global INVOKE_COUNT
    INVOKE_COUNT += 1
    start = time.time()
    time.sleep(float(event.get("hold_s", 0)))
    return {
        "env_id": ENV_ID,
        "init_pid": INIT_PID,
        "invoke_pid": os.getpid(),
        "init_epoch": INIT_EPOCH,
        "init_count": INIT_COUNT,
        "invoke_count": INVOKE_COUNT,
        "log_stream": context.log_stream_name,
        "request_id": context.aws_request_id,
        "env_var": os.environ.get("SIM2REAL_GEN", ""),
        "start": start,
        "end": time.time(),
    }
"""


def _make_zip(code, filename="index.py"):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(filename, code)
    return buf.getvalue()


_ROLES: dict = {}


def _role_arn(ctx) -> str:
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


def _create_function(lam, **kwargs):
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


def _wait_ready(lam, fn, timeout_s=120):
    """Poll until the function is Active AND any in-flight update has settled."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = lam.get_function_configuration(FunctionName=fn)
        if last["State"] == "Failed":
            raise AssertionError(f"{fn} entered Failed: {last.get('StateReason')!r}")
        if last.get("LastUpdateStatus") == "Failed":
            raise AssertionError(
                f"{fn} update Failed: {last.get('LastUpdateStatusReason')!r}"
            )
        if last["State"] == "Active" and last.get("LastUpdateStatus") in (None, "Successful"):
            return last
        time.sleep(1.0)
    raise AssertionError(f"{fn} never became Active/Successful in {timeout_s}s; last={last!r}")


def _invoke_sync(lam, fn, payload):
    resp = lam.invoke(
        FunctionName=fn, InvocationType="RequestResponse",
        Payload=json.dumps(payload).encode(),
    )
    raw = resp["Payload"].read()
    assert not resp.get("FunctionError"), (
        f"{fn} returned FunctionError={resp.get('FunctionError')!r}: {raw[:500]!r}"
    )
    assert raw, f"{fn} returned an empty payload: {resp!r}"
    return json.loads(raw)


def _bijection(bodies):
    """(env_id -> {log_stream}, log_stream -> {env_id}) as two multimaps."""
    fwd, rev = {}, {}
    for b in bodies:
        fwd.setdefault(b["env_id"], set()).add(b["log_stream"])
        rev.setdefault(b["log_stream"], set()).add(b["env_id"])
    return fwd, rev


def _per_env(bodies):
    """env_id -> the bodies it served, in invocation order."""
    groups: dict = {}
    for b in bodies:
        groups.setdefault(b["env_id"], []).append(b)
    return groups


def _assert_env_invariants(label, bodies):
    """Within each environment: counters 1..n in order, init once, one pid, epoch and stream."""
    for env, served in _per_env(bodies).items():
        counts = [b["invoke_count"] for b in served]
        assert counts == list(range(1, len(served) + 1)), (
            f"{label}: environment {env} must count its invocations 1..n in order, got {counts!r}"
        )
        assert all(b["init_count"] == 1 for b in served), (
            f"{label}: module scope must execute exactly once per environment, got init_count "
            f"values {[b['init_count'] for b in served]!r} in {env}"
        )
        assert len({b["init_epoch"] for b in served}) == 1, (
            f"{label}: INIT_EPOCH is minted at module scope and must not change within {env}, got "
            f"{[b['init_epoch'] for b in served]!r}"
        )
        assert len({b["init_pid"] for b in served}) == 1, (
            f"{label}: the init process must be the process still serving invocations in {env}, "
            f"got {[(b['init_pid'], b['invoke_pid']) for b in served]!r}"
        )
        assert len({b["log_stream"] for b in served}) == 1, (
            f"{label}: one execution environment must own exactly one log stream, got "
            f"{sorted({b['log_stream'] for b in served})!r} in {env}"
        )


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """Serialised invokes reuse execution environments whose init ran once (per env_id: counters climb
    1..n, one pid, epoch and log stream), and a configuration or code update moves every later
    invoke to environments disjoint from all earlier ones, starting fresh.
    """
    lam = ctx.client("lambda")
    fn = ctx.unique_name("sim2real-behav-fn-")
    _create_function(
        lam,
        FunctionName=fn, Runtime="python3.12", Handler="index.handler",
        Role=_role_arn(ctx), Code={"ZipFile": _make_zip(ENV_PROBE)},
        MemorySize=512, Timeout=60,
        Environment={"Variables": {"SIM2REAL_GEN": "g1"}},
        Tags={"sim2real:managed": "true"},
    )
    ctx.on_cleanup(lambda: _cleanup_fn(ctx, lam, fn))
    _wait_ready(lam, fn)

    # One slot, so the six invocations below run one at a time.
    conc = lam.put_function_concurrency(FunctionName=fn, ReservedConcurrentExecutions=1)
    assert conc["ReservedConcurrentExecutions"] == 1, conc

    warm = [_invoke_sync(lam, fn, {}) for _ in range(6)]

    # Lambda may recycle an environment at any time, so every per-environment invariant is graded
    # within each env_id rather than across the whole generation.
    warm_envs = set(_per_env(warm))
    _assert_env_invariants("before the update", warm)
    assert len(warm_envs) < len(warm), (
        f"{len(warm)} serialised invocations under ReservedConcurrentExecutions=1 each reported a "
        f"new env_id {sorted(warm_envs)!r}; the execution environment was never reused"
    )
    # Six distinct request ids, so one env_id is reuse and not a repeated response.
    warm_rids = {b["request_id"] for b in warm}
    assert len(warm_rids) == 6, (
        f"expected 6 distinct aws_request_ids, got {len(warm_rids)}: {sorted(warm_rids)!r}"
    )

    # A configuration update must retire every live environment.
    lam.update_function_configuration(
        FunctionName=fn, Environment={"Variables": {"SIM2REAL_GEN": "g2"}}
    )
    _wait_ready(lam, fn)
    gen2 = [_invoke_sync(lam, fn, {}) for _ in range(3)]

    assert gen2[0]["env_var"] == "g2", (
        f"the first post-update invocation must run with the new environment variable, got "
        f"{gen2[0]['env_var']!r}"
    )
    gen2_envs = {b["env_id"] for b in gen2}
    assert gen2_envs.isdisjoint(warm_envs), (
        f"UpdateFunctionConfiguration must invalidate every live execution environment; "
        f"post-update env_ids {sorted(gen2_envs)!r} still contain a pre-update environment "
        f"{sorted(warm_envs)!r}"
    )
    assert gen2[0]["invoke_count"] == 1 and gen2[0]["init_count"] == 1, (
        f"the post-update environment must be genuinely fresh, got invoke_count="
        f"{gen2[0]['invoke_count']!r} init_count={gen2[0]['init_count']!r}"
    )
    _assert_env_invariants("after the configuration update", gen2)

    # A code update invalidates too; only a trailing comment differs, so only the code sha changes.
    lam.update_function_code(
        FunctionName=fn, ZipFile=_make_zip(ENV_PROBE + "\n# sim2real generation 3\n")
    )
    _wait_ready(lam, fn)
    gen3 = [_invoke_sync(lam, fn, {}) for _ in range(3)]

    gen3_envs = {b["env_id"] for b in gen3}
    assert gen3_envs.isdisjoint(warm_envs | gen2_envs), (
        f"UpdateFunctionCode must invalidate every live environment and no retired environment "
        f"may reappear; got {sorted(gen3_envs)!r} against earlier "
        f"{sorted(warm_envs | gen2_envs)!r}"
    )
    assert gen3[0]["invoke_count"] == 1 and gen3[0]["init_count"] == 1, (
        f"the post-code-update environment must be genuinely fresh, got invoke_count="
        f"{gen3[0]['invoke_count']!r} init_count={gen3[0]['init_count']!r}"
    )
    _assert_env_invariants("after the code update", gen3)

    # Across three generations env_id and log stream map one-to-one.
    everything = warm + gen2 + gen3
    fwd, rev = _bijection(everything)
    multi_fwd = {e: s for e, s in fwd.items() if len(s) != 1}
    multi_rev = {s: e for s, e in rev.items() if len(e) != 1}
    assert not multi_fwd, (
        f"an execution environment reported more than one log stream, so log_stream_name is "
        f"fabricated per request rather than owned by the environment: {multi_fwd!r}"
    )
    assert not multi_rev, (
        f"a log stream was reported by more than one execution environment, so the "
        f"environment identity is decoupled from the stream: {multi_rev!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
