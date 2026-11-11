"""encryption-config-kms-enforced-on-put-trace-segments."""
from __future__ import annotations

import json
import os
import time

from behavioral_harness import tags

CHECK = "encryption-config-kms-enforced-on-put-trace-segments"
GROUP = "server-side"
SERVICES = ["xray"]


def _hex(n: int) -> str:
    return os.urandom(n).hex()


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:data-plane", "concern:representation", "dp:api", "plane:data", "resource:account-singleton:xray-encryption")
def run(ctx) -> None:
    """PutEncryptionConfig with `alias/aws/xray` transitions UPDATING -> ACTIVE with the alias
    resolved to the key's ARN, and a segment submitted afterwards is stored and returned by
    BatchGetTraces.
    """
    xray = ctx.client("xray")
    kms = ctx.client("kms")

    expected_key_arn = kms.describe_key(KeyId="alias/aws/xray")["KeyMetadata"]["Arn"]

    initial_cfg = xray.get_encryption_config()["EncryptionConfig"]
    # Wait for any previous config change (e.g. from an earlier check run) to finish
    # settling before starting ours -- PutEncryptionConfig rejects a new change while
    # one is still being applied.
    _wait_until_settled(ctx, timeout_s=40.0)

    # Revert to default (NONE) encryption on cleanup so the account isn't left under
    # KMS encryption from this check. Retries the same "previous change is currently
    # being applied" collision the activation above tolerates -- cleanup runs right
    # after this check's own PutEncryptionConfig, while that change may still be
    # settling, well within the 60s cleanup budget.
    ctx.on_cleanup(
        lambda: _put_encryption_config_with_retry(ctx, Type="NONE", timeout_s=45.0)
    )

    put_cfg = _put_encryption_config_with_retry(
        ctx, Type="KMS", KeyId="alias/aws/xray", timeout_s=30.0
    )
    assert put_cfg["EncryptionConfig"]["Type"] == "KMS", (
        f"expected PutEncryptionConfig to echo Type=KMS, got {put_cfg['EncryptionConfig']!r}"
    )

    # X-Ray's account-wide switch to a KMS key can stay UPDATING past 300 s; 900 s covers that
    # variance and leaves room for teardown within the suite budget.
    status, last_cfg = _poll_encryption_status(ctx, timeout_s=900.0)
    assert status == "ACTIVE", (
        f"encryption config never became ACTIVE, last saw {status!r} "
        f"(last full config: {last_cfg!r}, config before this check ran: {initial_cfg!r})"
    )

    cfg = xray.get_encryption_config()["EncryptionConfig"]
    assert cfg["Type"] == "KMS", f"expected Type=KMS once ACTIVE, got {cfg!r}"
    # The AWS-managed alias must resolve to that key's own real ARN (from
    # DescribeKey) once active, not stay the literal "alias/aws/xray" string.
    assert cfg["KeyId"] == expected_key_arn, (
        f"expected the alias to resolve to its key ARN {expected_key_arn!r}, got {cfg['KeyId']!r}"
    )

    now = time.time()
    trace_id = f"1-{int(now):08x}-{_hex(12)}"
    segment_doc = json.dumps(
        {
            "name": ctx.unique_name("sim2real-xray-enc-svc-"),
            "id": _hex(8),
            "trace_id": trace_id,
            "start_time": now,
            "end_time": now + 0.25,
        }
    )
    put_resp = xray.put_trace_segments(TraceSegmentDocuments=[segment_doc])
    assert not put_resp.get("UnprocessedTraceSegments"), (
        f"PutTraceSegments rejected segments under KMS encryption: "
        f"{put_resp.get('UnprocessedTraceSegments')}"
    )

    # The mutating call's own response only says the segment was accepted for
    # processing -- confirm it was actually stored and is readable back through an
    # independent operation (BatchGetTraces) while KMS encryption is active.
    traces = _poll_batch_get_traces(ctx, trace_id, timeout_s=300.0)
    assert len(traces) == 1, f"expected exactly one trace for {trace_id!r}, got {traces!r}"
    assert traces[0]["Id"] == trace_id, f"expected trace id {trace_id!r}, got {traces[0]['Id']!r}"
    assert len(traces[0].get("Segments", [])) == 1, (
        f"expected exactly one stored segment for {trace_id!r}, got {traces[0].get('Segments')!r}"
    )


# ===== helpers =====
def _wait_until_settled(ctx, timeout_s):
    """Waits until GetEncryptionConfig reports a terminal (non-UPDATING) status, so a
    change left in flight by a prior run doesn't collide with this check's own
    PutEncryptionConfig call."""
    xray = ctx.client("xray")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        cfg = xray.get_encryption_config()["EncryptionConfig"]
        if cfg.get("Status") != "UPDATING":
            return
        time.sleep(5.0)


def _put_encryption_config_with_retry(ctx, timeout_s, **kwargs):
    """Retries PutEncryptionConfig while AWS reports another change is still being
    applied (a transient collision with a prior run's in-flight change)."""
    from botocore.exceptions import ClientError

    xray = ctx.client("xray")
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return xray.put_encryption_config(**kwargs)
        except ClientError as err:
            code = err.response["Error"]["Code"]
            message = err.response["Error"].get("Message", "")
            if code == "InvalidRequestException" and "previous change" in message.lower():
                if time.monotonic() >= deadline:
                    raise
                time.sleep(5.0)
                continue
            raise


def _poll_batch_get_traces(ctx, trace_id, timeout_s):
    xray = ctx.client("xray")
    deadline = time.monotonic() + timeout_s
    last = []
    while True:
        last = xray.batch_get_traces(TraceIds=[trace_id])["Traces"]
        if len(last) >= 1:
            return last
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"trace {trace_id!r} not retrievable via BatchGetTraces within {timeout_s}s"
            )
        time.sleep(2.0)


def _poll_encryption_status(ctx, timeout_s):
    xray = ctx.client("xray")
    deadline = time.monotonic() + timeout_s
    last_status = None
    last_cfg = None
    while time.monotonic() < deadline:
        last_cfg = xray.get_encryption_config()["EncryptionConfig"]
        last_status = last_cfg.get("Status")
        if last_status == "ACTIVE" and last_cfg.get("Type") == "KMS":
            return last_status, last_cfg
        time.sleep(5.0)
    return last_status, last_cfg


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)


