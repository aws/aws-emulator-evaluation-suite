"""concurrent-detach-data-source-race-idempotent."""
from __future__ import annotations

import re
import time
import uuid
from concurrent.futures import ThreadPoolExecutor

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "concurrent-detach-data-source-race-idempotent"
GROUP = "concurrency"
SERVICES = ["opensearch"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Two concurrent DetachDataSource calls on an ATTACHED data source leave at least one success echoing
    the domain ARN and any loser failing only with ConflictException; the attachment is then gone and a
    re-attach reaches ATTACHED.
    """
    opensearch = ctx.client("opensearch")
    domain_name, domain_arn = _create_minimal_domain(ctx, "dt")
    _wait_domain_active(ctx, domain_name)
    app_id = _create_application(ctx, "dt")

    opensearch.attach_data_source(
        id=app_id, dataSourceArn=domain_arn, clientToken=str(uuid.uuid4())
    )
    status = _wait_attachment_status(ctx, app_id, domain_arn, {"ATTACHED", "FAILED"})
    assert status == "ATTACHED", f"attachment did not reach ATTACHED (got {status!r})"

    def _detach():
        return opensearch.detach_data_source(id=app_id, dataSourceArn=domain_arn)

    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(_detach) for _ in range(2)]
        results = []
        for fut in futures:
            try:
                results.append(("ok", fut.result()))
            except Exception as exc:  # noqa: BLE001
                code = exc.response["Error"]["Code"] if hasattr(exc, "response") else None
                results.append(("err", code))

    successes = [r for r in results if r[0] == "ok"]
    failures = [r for r in results if r[0] == "err"]
    # Empirically both racing calls succeed (idempotent detach); if the emulator/AWS instead
    # serializes them, a rejected loser must be exactly ConflictException, never anything else.
    assert len(successes) >= 1, f"expected at least one DetachDataSource to succeed: {results}"
    for _, code in failures:
        assert code == "ConflictException", f"unexpected failure code {code!r} (expected ConflictException)"
    for _, resp in successes:
        assert resp["dataSourceArn"] == domain_arn, f"unexpected dataSourceArn in response: {resp!r}"

    # Effect check: the attachment is gone (removed exactly once, no leftover/duplicate state
    # from the race between the two calls).
    remaining = _wait_for_absence(ctx, app_id, domain_arn)
    assert remaining is False, f"attachment for {domain_arn!r} was still listed after detach"

    # Positive control: re-attaching afterwards must succeed -- proves the application is not
    # left in a stuck/broken state by the concurrent detach race.
    reattach = opensearch.attach_data_source(
        id=app_id, dataSourceArn=domain_arn, clientToken=str(uuid.uuid4())
    )
    assert reattach["dataSourceArn"] == domain_arn, f"unexpected dataSourceArn in re-attach response: {reattach!r}"
    status2 = _wait_attachment_status(ctx, app_id, domain_arn, {"ATTACHED", "FAILED"})
    assert status2 == "ATTACHED", f"control re-attach did not reach ATTACHED (got {status2!r})"


def _short_name(ctx, tag: str, maxlen: int) -> str:
    raw = ctx.unique_name(f"os{tag}").lower()
    raw = re.sub(r"[^a-z0-9-]", "-", raw)
    raw = re.sub(r"-+", "-", raw).strip("-")
    if len(raw) > maxlen:
        keep_tail = maxlen - 6
        raw = raw[:6] + raw[-keep_tail:]
    if not raw or not raw[0].isalpha():
        raw = "a" + raw[1:]
    return raw[:maxlen]


def _create_minimal_domain(ctx, tag: str):
    opensearch = ctx.client("opensearch")
    name = _short_name(ctx, tag, 28)
    resp = opensearch.create_domain(
        DomainName=name,
        ClusterConfig={
            "InstanceType": "t3.small.search",
            "InstanceCount": 1,
            "DedicatedMasterEnabled": False,
            "ZoneAwarenessEnabled": False,
        },
        EBSOptions={"EBSEnabled": True, "VolumeType": "gp3", "VolumeSize": 10},
    )
    ctx.on_cleanup(lambda: _safe_delete_domain(ctx, name))
    return name, resp["DomainStatus"]["ARN"]


def _safe_delete_domain(ctx, name: str) -> None:
    try:
        ctx.client("opensearch").delete_domain(DomainName=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _wait_domain_active(ctx, name: str, timeout_s: float = 2700, interval_s: float = 30):
    opensearch = ctx.client("opensearch")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        status = opensearch.describe_domain(DomainName=name)["DomainStatus"]
        if status.get("Created") and not status.get("Processing"):
            return status
        time.sleep(interval_s)
    raise AssertionError(f"domain {name} did not become active within {timeout_s}s")


def _create_application(ctx, tag: str) -> str:
    opensearch = ctx.client("opensearch")
    name = _short_name(ctx, tag, 30)
    try:
        resp = opensearch.create_application(name=name)
    except Exception as exc:  # noqa: BLE001
        code = exc.response["Error"]["Code"] if hasattr(exc, "response") else None
        if code == "DisabledOperationException":
            raise AssertionError(
                "OpenSearch Applications feature is not enabled for this account/region"
            ) from exc
        raise
    app_id = resp["id"]
    ctx.on_cleanup(lambda: _safe_delete_application(ctx, app_id))
    _wait_application_active(ctx, app_id)
    return app_id


def _safe_delete_application(ctx, app_id: str) -> None:
    try:
        ctx.client("opensearch").delete_application(id=app_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _wait_application_active(ctx, app_id: str, timeout_s: float = 300, interval_s: float = 10):
    opensearch = ctx.client("opensearch")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        status = opensearch.get_application(id=app_id)["status"]
        if status == "ACTIVE":
            return
        if status == "FAILED":
            raise AssertionError(f"application {app_id} entered FAILED status")
        time.sleep(interval_s)
    raise AssertionError(f"application {app_id} did not become ACTIVE within {timeout_s}s")


def _wait_attachment_status(ctx, app_id: str, data_source_arn: str, terminal: set, timeout_s: float = 300, interval_s: float = 10):
    opensearch = ctx.client("opensearch")
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        status = opensearch.describe_data_source_attachment(id=app_id, dataSourceArn=data_source_arn)["status"]
        if status in terminal:
            return status
        time.sleep(interval_s)
    raise AssertionError(
        f"attachment for {data_source_arn!r} did not reach {terminal} within {timeout_s}s (last status: {status!r})"
    )


def _wait_for_absence(ctx, app_id: str, data_source_arn: str, timeout_s: float = 300, interval_s: float = 10) -> bool:
    opensearch = ctx.client("opensearch")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        attachments = opensearch.list_data_source_attachments(id=app_id).get("attachments", [])
        if not any(a["dataSourceArn"] == data_source_arn for a in attachments):
            return False
        time.sleep(interval_s)
    return True


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
