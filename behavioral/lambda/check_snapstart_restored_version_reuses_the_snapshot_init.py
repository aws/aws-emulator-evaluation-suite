"""snapstart-restored-version-reuses-the-snapshot-init."""

from __future__ import annotations

import concurrent.futures
import io
import json
import textwrap
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "snapstart-restored-version-reuses-the-snapshot-init"
GROUP = 'state-machine'
SERVICES = ['lambda']

# Each invocation holds its execution environment open this long, so a burst of BURST calls is
# forced into BURST DISTINCT environments instead of being served by one warm reuse.
HOLD_S = 6
BURST = 3

# INIT_ID is minted once per real module initialisation. RESTORE_ID is minted by the
# after-restore runtime hook, which fires once per restore from the snapshot. On a SnapStart
# version the init is snapshotted and replayed, so INIT_ID must be IDENTICAL across environments
# while RESTORE_ID must DIFFER — that pair is the signature of a restore.
HANDLER = """\
import time
import uuid

INIT_ID = str(uuid.uuid4())
RESTORE_ID = "no-restore-hook-ran"

try:
    from snapshot_restore_py import register_after_restore
    HOOK_IMPORT = "ok"

    def _after_restore():
        global RESTORE_ID
        RESTORE_ID = str(uuid.uuid4())

    register_after_restore(_after_restore)
except Exception as exc:
    HOOK_IMPORT = "import-failed: %r" % (exc,)


def handler(event, context):
    time.sleep(float(event.get("hold_s", 0)))
    return {
        "init_id": INIT_ID,
        "restore_id": RESTORE_ID,
        "hook_import": HOOK_IMPORT,
        "log_stream": context.log_stream_name,
    }
"""


def _make_zip(code, filename="index.py"):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(filename, textwrap.dedent(code))
    return buf.getvalue()


_ROLES: dict = {}
_BASIC_EXEC = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"


def _exec_role_arn(ctx):
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
    iam.attach_role_policy(RoleName=name, PolicyArn=_BASIC_EXEC)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=name, PolicyArn=_BASIC_EXEC))
    _ROLES[id(ctx)] = arn
    return arn


def _create_function_retrying(lam, **kwargs):
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
        # Deleting the function deletes every published version with it.
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


def _wait_snapstart_on(lam, qualified, timeout_s=300):
    """Poll a published version until it is Active AND its snapshot is optimized."""
    def _probe():
        cfg = lam.get_function(FunctionName=qualified)["Configuration"]
        if cfg.get("State") == "Failed":
            raise AssertionError(
                f"{qualified} entered State=Failed while optimizing the snapshot: "
                f"{cfg.get('StateReason')!r}"
            )
        status = (cfg.get("SnapStart") or {}).get("OptimizationStatus")
        return cfg if cfg.get("State") == "Active" and status == "On" else None

    cfg = _poll(_probe, timeout_s)
    assert cfg is not None, (
        f"{qualified} never reached State=Active with SnapStart.OptimizationStatus=='On' within "
        f"{timeout_s}s — SnapStart optimization is a REQUIRED transition here, so a stall is a "
        f"failure and never a skip"
    )
    return cfg


def _burst(lam, target):
    """Invoke `target` BURST times concurrently; every call holds its sandbox for HOLD_S."""
    def _call(_i):
        resp = lam.invoke(
            FunctionName=target, Payload=json.dumps({"hold_s": HOLD_S}).encode()
        )
        raw = resp["Payload"].read()
        assert resp["StatusCode"] == 200, f"{target}: StatusCode {resp['StatusCode']!r} {raw!r}"
        assert "FunctionError" not in resp, (
            f"{target} failed with FunctionError={resp.get('FunctionError')!r}: {raw!r}"
        )
        return json.loads(raw)

    with concurrent.futures.ThreadPoolExecutor(max_workers=BURST) as ex:
        futures = [ex.submit(_call, i) for i in range(BURST)]
        return [f.result(timeout=180) for f in futures]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """Environments of a SnapStart version share one snapshotted INIT_ID and fire the after-restore
    hook each, while the $LATEST control re-initializes every environment and never fires it.

    Reference: https://docs.aws.amazon.com/lambda/latest/dg/snapstart.html
    """
    lam = ctx.client("lambda")
    fn = ctx.unique_name("sim2real-behav-snapfn-")
    _create_function_retrying(
        lam,
        FunctionName=fn, Runtime="python3.12", Handler="index.handler",
        Role=_exec_role_arn(ctx), Code={"ZipFile": _make_zip(HANDLER)},
        MemorySize=512, Timeout=60,
        Tags={"sim2real": CHECK},
    )
    ctx.on_cleanup(lambda: _cleanup_fn(ctx, lam, fn))
    _wait_active(lam, fn)

    lam.update_function_configuration(
        FunctionName=fn, SnapStart={"ApplyOn": "PublishedVersions"}
    )
    cfg = _wait_active(lam, fn)
    assert (cfg.get("SnapStart") or {}).get("ApplyOn") == "PublishedVersions", (
        f"SnapStart.ApplyOn did not round-trip on $LATEST: {cfg.get('SnapStart')!r}"
    )

    published = lam.publish_version(FunctionName=fn)
    version = published["Version"]
    qualified = f"{fn}:{version}"
    ver_cfg = _wait_snapstart_on(lam, qualified)
    opt_status = (ver_cfg.get("SnapStart") or {}).get("OptimizationStatus")
    assert opt_status == "On", (
        f"the published version reports SnapStart.OptimizationStatus={opt_status!r}, so nothing "
        f"was snapshotted and the restore claim below would be vacuous"
    )

    ver_bodies = _burst(lam, qualified)
    assert all(b["hook_import"] == "ok" for b in ver_bodies), (
        f"snapshot_restore_py did not import inside the runtime, so the after-restore hook was "
        f"never registered and RESTORE_ID proves nothing: "
        f"{[b['hook_import'] for b in ver_bodies]!r}"
    )
    ver_inits = {b["init_id"] for b in ver_bodies}
    ver_restores = [b["restore_id"] for b in ver_bodies]

    # BURST distinct restore ids means BURST distinct execution environments really were used,
    # so the single shared INIT_ID below cannot be one warm reuse.
    assert len(set(ver_restores)) == BURST, (
        f"the after-restore hook did not produce a distinct value per environment "
        f"({sorted(set(ver_restores))!r} across {BURST} concurrent held invocations) — either the "
        f"hook ran once for all of them or the burst was served by fewer environments than it "
        f"needs, and in both cases the shared-init assertion would be meaningless"
    )
    assert "no-restore-hook-ran" not in ver_restores, (
        f"an invocation of the SnapStart version ran without the after-restore hook firing: "
        f"{ver_restores!r}"
    )
    assert len(ver_inits) == 1, (
        f"the SnapStart version re-initialized instead of restoring a snapshot: {BURST} "
        f"environments reported {len(ver_inits)} distinct INIT_IDs {sorted(ver_inits)!r}. A "
        f"restored environment must replay the snapshotted module scope, never re-run it"
    )

    # Control: the same code on $LATEST, where SnapStart does not apply.
    latest_bodies = _burst(lam, fn)
    latest_inits = [b["init_id"] for b in latest_bodies]
    assert len(set(latest_inits)) == BURST, (
        f"the non-SnapStart control did not re-initialize between cold environments: "
        f"{latest_inits!r}. Without that the version's shared INIT_ID could just mean this "
        f"handler mints a constant"
    )
    assert set(latest_inits).isdisjoint(ver_inits), (
        f"a $LATEST environment reported the same INIT_ID as the snapshotted version "
        f"({sorted(ver_inits)!r}) — the two must be separate initialisations"
    )
    assert all(b["restore_id"] == "no-restore-hook-ran" for b in latest_bodies), (
        f"the after-restore hook fired on $LATEST, where SnapStart is not applied: "
        f"{[b['restore_id'] for b in latest_bodies]!r}"
    )
    assert len({b["log_stream"] for b in latest_bodies}) == BURST, (
        f"the $LATEST burst was served by fewer than {BURST} execution environments "
        f"({[b['log_stream'] for b in latest_bodies]!r}), so its re-initialization leg proves "
        f"less than it should"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
