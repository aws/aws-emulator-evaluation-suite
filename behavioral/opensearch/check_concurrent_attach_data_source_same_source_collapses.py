"""concurrent-attach-data-source-same-source-collapses."""
from __future__ import annotations

import re
import time
from concurrent.futures import ThreadPoolExecutor

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "concurrent-attach-data-source-same-source-collapses"
GROUP = "concurrency"
SERVICES = ["opensearch"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Two concurrent AttachDataSource calls with the same clientToken both succeed with one attachmentId,
    never a ConflictException, and the application holds exactly one attachment for the domain.
    """
    opensearch = ctx.client("opensearch")
    # NOTE: AttachDataSource only requires the domain to *exist* (DescribeDomain resolves it
    # immediately after CreateDomain returns); it does not require the domain to have finished
    # provisioning (Created=true/Processing=false), so we deliberately skip the long
    # create-to-active wait (which can take 15-45 min) and use the domain ARN right away.
    domain_name, domain_arn = _create_minimal_domain(ctx, "ad")

    app_id = _create_application(ctx, "ad")

    import uuid

    token = str(uuid.uuid4())  # AttachDataSource requires clientToken length >= 33 (empirically;
    # the published docs say min length 1, but real AWS enforces >= 33 for this field)

    def _attach():
        return opensearch.attach_data_source(
            id=app_id, dataSourceArn=domain_arn, clientToken=token
        )

    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(_attach) for _ in range(2)]
        results = []
        for fut in futures:
            try:
                results.append(("ok", fut.result()))
            except Exception as exc:  # noqa: BLE001
                code = exc.response["Error"]["Code"] if hasattr(exc, "response") else None
                msg = exc.response["Error"].get("Message") if hasattr(exc, "response") else str(exc)
                results.append(("err", (code, msg)))

    successes = [r for r in results if r[0] == "ok"]
    failures = [r for r in results if r[0] == "err"]
    assert len(successes) == 2, (
        f"AttachDataSource is documented idempotent for a shared clientToken -- both concurrent "
        f"callers must see the retry succeed, not just one: {results}"
    )
    assert failures == [], f"shared clientToken must never surface a ConflictException between racers: {results}"

    # Idempotent retries with the same clientToken must resolve to the SAME attachmentId --
    # not two divergent attachment records.
    attachment_ids = {r[1]["attachmentId"] for r in successes}
    assert len(attachment_ids) == 1, (
        f"expected all successful calls sharing clientToken={token!r} to return the same "
        f"attachmentId, got {attachment_ids}: {results}"
    )

    # Effect check: exactly one attachment exists for this dataSourceArn -- the shared
    # clientToken collapsed the race to a single record, not two duplicate attachments.
    attachments = _wait_for_stable_attachments(ctx, app_id)
    matching = [a for a in attachments if a["dataSourceArn"] == domain_arn]
    assert len(matching) == 1, f"expected exactly 1 attachment for {domain_arn!r}, found {len(matching)}: {attachments}"


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
        TagList=[{"Key": "sim2real:managed", "Value": "true"}],
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
        resp = opensearch.create_application(
            name=name, tagList=[{"Key": "sim2real:managed", "Value": "true"}]
        )
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


def _wait_for_stable_attachments(ctx, app_id: str, timeout_s: float = 300, interval_s: float = 10):
    opensearch = ctx.client("opensearch")
    deadline = time.monotonic() + timeout_s
    last = []
    while time.monotonic() < deadline:
        last = opensearch.list_data_source_attachments(id=app_id).get("attachments", [])
        if last and all(a.get("status") != "PENDING" for a in last):
            return last
        time.sleep(interval_s)
    return last


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
