"""ephemeral-storage-size-is-enforced-not-only-reported."""

from __future__ import annotations

import errno
import io
import json
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "ephemeral-storage-size-is-enforced-not-only-reported"
GROUP = "ephemeral_storage"
SERVICES = ["lambda"]

_SMALL_MB = 512  # the documented minimum: a fixed API constant, not an account-adjustable quota
_LARGE_MB = 2048  # inside the documented 512..10240 range

_HANDLER = """\
import errno
import os

CHUNK_MB = 8
CHUNK = b"\\0" * (CHUNK_MB * 1024 * 1024)
PATH = "/tmp/sim2real-ephemeral-fill.bin"


def _mb(blocks, frsize):
    return (blocks * frsize) // (1024 * 1024)


def _stat():
    st = os.statvfs("/tmp")
    return _mb(st.f_blocks, st.f_frsize), _mb(st.f_bavail, st.f_frsize)


def handler(event, context):
    total_mb, free_mb = _stat()
    result = {"total_mb": total_mb, "free_before_mb": free_mb}
    if event.get("mode") == "report":
        return result

    target_mb = int(event["target_mb"])
    written_mb = 0
    err = None
    try:
        with open(PATH, "wb") as fh:
            while written_mb < target_mb:
                fh.write(CHUNK)
                fh.flush()
                written_mb += CHUNK_MB
    except OSError as exc:
        err = {
            "errno": exc.errno,
            "name": errno.errorcode.get(exc.errno),
            "msg": str(exc)[:200],
        }
    finally:
        if os.path.exists(PATH):
            os.remove(PATH)

    total_after, free_after = _stat()
    result.update({
        "target_mb": target_mb,
        "written_mb": written_mb,
        "error": err,
        "free_after_mb": free_after,
        "total_after_mb": total_after,
    })
    return result
"""


@tags(
    "axis:happy-path",
    "cap:c3",
    "concern:data-plane",
    "concern:negative-classes",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """A write past EphemeralStorage.Size fails with ENOSPC on a 512 MB function and its space is
    reclaimed, while a 2048 MB twin accepts the byte-identical write: the size is enforced.
    """
    lam = ctx.client("lambda")
    iam = ctx.client("iam")

    role_arn = _create_execution_role(ctx, iam)
    code = _make_zip({"index.py": _HANDLER})

    small = _deploy(ctx, lam, role_arn, code, _SMALL_MB, "small")
    large = _deploy(ctx, lam, role_arn, code, _LARGE_MB, "large")

    # ---- what each function says about its own filesystem ----
    small_report = _invoke_json(lam, small, {"mode": "report"})
    large_report = _invoke_json(lam, large, {"mode": "report"})
    for name, report, configured in (
        (small, small_report, _SMALL_MB),
        (large, large_report, _LARGE_MB),
    ):
        # statvfs reports slightly above the configured size (filesystem-metadata overhead,
        # e.g. 512 -> 524 MB), so the band is +-10%.
        assert 0.9 * configured <= report["total_mb"] <= 1.1 * configured, (
            f"{name} was configured with EphemeralStorage.Size={configured} MB but statvfs reports "
            f"total {report['total_mb']} MB (expected between {int(0.9 * configured)} and "
            f"{int(1.1 * configured)})"
        )
    small_free = small_report["free_before_mb"]
    large_free = large_report["free_before_mb"]
    assert small_free >= 256, (
        f"the 512 MB function reports only {small_free} MB free, which leaves no room to calibrate "
        f"an in-bounds write; full report {small_report!r}"
    )
    assert large_free >= small_free + 1024, (
        f"the 2048 MB twin must have substantially more free space than the 512 MB function for the "
        f"twin control to mean anything: small={small_free} MB free, large={large_free} MB free"
    )

    # Sizes derive from the free space the function reports, so nothing about the account is pinned.
    in_bounds_mb = small_free - 64
    over_bounds_mb = small_free + 128

    # ---- beat 1: positive control — both functions write an in-bounds file successfully ----
    for name, res in (
        (small, _invoke_json(lam, small, {"target_mb": in_bounds_mb})),
        (large, _invoke_json(lam, large, {"target_mb": in_bounds_mb})),
    ):
        assert res["error"] is None, (
            f"positive control failed: {name} could not write {in_bounds_mb} MB, which is inside "
            f"its own reported free space; error={res['error']!r}"
        )
        assert res["written_mb"] >= in_bounds_mb, (
            f"positive control on {name} reported only {res['written_mb']} MB written of the "
            f"{in_bounds_mb} MB requested, with no error"
        )

    # ---- beats 2-4: break exactly one thing (the requested size), on both twins at once ----
    small_over = _invoke_json(lam, small, {"target_mb": over_bounds_mb})
    large_over = _invoke_json(lam, large, {"target_mb": over_bounds_mb})

    err = small_over["error"]
    assert err is not None, (
        f"the 512 MB function accepted a {over_bounds_mb} MB write although it reported only "
        f"{small_free} MB free: it claims {small_over['written_mb']} MB written with no error, and "
        f"{small_over['free_after_mb']} MB free afterwards — EphemeralStorage.Size is not enforced"
    )
    assert err.get("errno") == errno.ENOSPC, (
        f"exceeding EphemeralStorage.Size must fail with ENOSPC ({errno.ENOSPC}); the 512 MB "
        f"function raised errno {err.get('errno')!r} ({err.get('name')!r}): {err.get('msg')!r}"
    )
    assert small_over["written_mb"] < over_bounds_mb, (
        f"the 512 MB function reported errno {err.get('errno')} yet claims all {over_bounds_mb} MB "
        f"were written ({small_over['written_mb']} MB)"
    )
    assert small_over["written_mb"] >= in_bounds_mb, (
        f"the 512 MB function refused after only {small_over['written_mb']} MB, well short of the "
        f"{in_bounds_mb} MB it demonstrably accepts — this reads as a broken write path, not a "
        f"capacity ceiling"
    )
    # effect absent: the partial file is gone and its space is back.
    assert small_over["free_after_mb"] >= in_bounds_mb, (
        f"after the failed write and unlink the 512 MB function reports only "
        f"{small_over['free_after_mb']} MB free (it had {small_free} MB before), so the partial "
        f"file's space was not reclaimed"
    )

    # ---- beat 5: the twin control accepted the byte-identical request ----
    assert large_over["error"] is None, (
        f"the 2048 MB twin must accept the same {over_bounds_mb} MB write that the 512 MB function "
        f"refused; it failed with {large_over['error']!r}"
    )
    assert large_over["written_mb"] >= over_bounds_mb, (
        f"the 2048 MB twin reported no error but only {large_over['written_mb']} MB of the "
        f"{over_bounds_mb} MB requested"
    )

    # ---- beat 6: restore — the identical in-bounds call still succeeds on the small function ----
    restored = _invoke_json(lam, small, {"target_mb": in_bounds_mb})
    assert restored["error"] is None, (
        f"the 512 MB function no longer accepts the {in_bounds_mb} MB write that succeeded before "
        f"the ENOSPC, so the refusal was not a recoverable capacity ceiling: {restored['error']!r}"
    )


def _make_zip(files: dict[str, str]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, content in files.items():
            zf.writestr(name, content)
    return buf.getvalue()


def _deploy(ctx, lam, role_arn: str, code: bytes, size_mb: int, label: str) -> str:
    fn = ctx.unique_name(f"sim2real-behav-ephem-{label}-")
    _create_function(
        ctx,
        lam,
        FunctionName=fn,
        Runtime="python3.12",
        Role=role_arn,
        Handler="index.handler",
        Code={"ZipFile": code},
        MemorySize=1024,
        Timeout=300,
        EphemeralStorage={"Size": size_mb},
        Tags={"sim2real": CHECK, "ephemeral-mb": str(size_mb)},
    )
    _wait_active(lam, fn)
    stored = lam.get_function_configuration(FunctionName=fn)["EphemeralStorage"]["Size"]
    assert stored == size_mb, (
        f"{fn} was created with EphemeralStorage.Size={size_mb} but the control plane reports "
        f"{stored}"
    )
    return fn


def _invoke_json(lam, fn: str, payload: dict) -> dict:
    resp = lam.invoke(
        FunctionName=fn,
        InvocationType="RequestResponse",
        Payload=json.dumps(payload).encode(),
    )
    body = resp["Payload"].read().decode()
    assert "FunctionError" not in resp, (
        f"{fn} raised on payload {payload!r} instead of reporting its filesystem state: "
        f"{resp.get('FunctionError')} {body[:300]}"
    )
    assert resp["StatusCode"] == 200, (
        f"Invoke({fn}) returned StatusCode {resp['StatusCode']}: {body[:300]}"
    )
    parsed = json.loads(body)
    for key in ("total_mb", "free_before_mb"):
        if key not in parsed:
            raise AssertionError(f"{fn} response is missing {key!r}: {parsed!r}")
    return parsed


def _create_execution_role(ctx, iam) -> str:
    """Create this check's own execution role in-check, tagged so a leftover can be found by tag."""
    role_name = ctx.unique_name("sim2real-behav-ephem-role-")
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
    return role["Role"]["Arn"]


def _create_function(ctx, lam, **kwargs):
    """CreateFunction, retrying only the documented role-propagation refusal; raises on deadline."""
    name = kwargs["FunctionName"]
    ctx.on_cleanup(lambda: _delete_function(ctx, lam, name))
    deadline = time.monotonic() + 90.0
    last = None
    while time.monotonic() < deadline:
        try:
            return lam.create_function(**kwargs)
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code not in ("InvalidParameterValueException", "ResourceConflictException"):
                raise
            last = exc
            time.sleep(3)
    raise AssertionError(f"CreateFunction({name}) never succeeded within 90s; last error {last}")


def _delete_function(ctx, lam, name: str) -> None:
    lam.delete_function(FunctionName=name)
    ctx.client("logs").delete_log_group(logGroupName=f"/aws/lambda/{name}")


def _wait_active(lam, name: str, timeout_s: float = 120.0) -> dict:
    def _probe():
        cfg = lam.get_function_configuration(FunctionName=name)
        if cfg.get("State") == "Failed":
            raise AssertionError(
                f"{name} entered State=Failed: {cfg.get('StateReasonCode')} {cfg.get('StateReason')}"
            )
        return cfg

    return _poll_until(
        _probe,
        lambda cfg: cfg.get("State") == "Active",
        timeout_s=timeout_s,
        interval_s=2.0,
        description=f"{name} reaching State=Active",
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
