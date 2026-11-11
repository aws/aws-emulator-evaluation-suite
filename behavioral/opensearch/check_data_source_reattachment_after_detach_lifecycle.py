"""data-source-reattachment-after-detach-lifecycle."""
from __future__ import annotations

import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "data-source-reattachment-after-detach-lifecycle"
GROUP = "state-machine"
SERVICES = ["opensearch"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Attach, detach and re-attach of one domain each settle as expected: the re-attach gets a new
    attachmentId with status ATTACHED, and the detach leaves no record of the first attachment.
    """
    domain_name = _domain_name(ctx, "dsa")
    _create_minimal_domain(ctx, domain_name)
    domain_status = _wait_domain_active(ctx, domain_name)
    domain_arn = domain_status["ARN"]

    opensearch = ctx.client("opensearch")
    app_id = opensearch.create_application(
        name=_app_name(ctx), tagList=[{"Key": "sim2real", "Value": "dsa"}]
    )["id"]
    ctx.on_cleanup(lambda: _delete_application(ctx, app_id))
    _wait_application_active(ctx, app_id)

    # Cycle 1: attach.
    first = opensearch.attach_data_source(id=app_id, dataSourceArn=domain_arn)
    first_attachment = _wait_attachment_status(ctx, app_id, domain_arn, "ATTACHED")
    first_attachment_id = first_attachment["attachmentId"]
    assert first["attachmentId"] == first_attachment_id, (
        f"AttachDataSource returned attachmentId {first['attachmentId']!r}, but the "
        f"independent describe reports {first_attachment_id!r} for the same pair"
    )
    assert first_attachment["status"] == "ATTACHED", (
        f"expected first attachment to settle at ATTACHED, got {first_attachment['status']!r}"
    )

    # Detach: the attachment record must be fully removed, not left in some other state.
    opensearch.detach_data_source(id=app_id, dataSourceArn=domain_arn)
    _wait_attachment_removed(ctx, app_id, domain_arn)
    attachments_after_detach = opensearch.list_data_source_attachments(id=app_id)["attachments"]
    assert not any(a["dataSourceArn"] == domain_arn for a in attachments_after_detach), (
        f"detached attachment for {domain_arn} is still listed: {attachments_after_detach}"
    )

    # Cycle 2: reattach the same data source -- must produce a fresh attachment record.
    second = opensearch.attach_data_source(id=app_id, dataSourceArn=domain_arn)
    ctx.on_cleanup(lambda: _detach(ctx, app_id, domain_arn))
    second_attachment = _wait_attachment_status(ctx, app_id, domain_arn, "ATTACHED")
    second_attachment_id = second_attachment["attachmentId"]
    assert second["attachmentId"] == second_attachment_id, (
        f"AttachDataSource returned attachmentId {second['attachmentId']!r}, but the "
        f"independent describe reports {second_attachment_id!r} for the same pair"
    )
    assert second_attachment["status"] == "ATTACHED", (
        f"expected reattachment to settle at ATTACHED, got {second_attachment['status']!r}"
    )
    assert second_attachment_id != first_attachment_id, (
        f"reattach after detach reused attachmentId {second_attachment_id!r} from the "
        f"detached cycle instead of minting a fresh one"
    )

    listed = opensearch.list_data_source_attachments(id=app_id)["attachments"]
    matches = [a for a in listed if a["dataSourceArn"] == domain_arn]
    assert len(matches) == 1, (
        f"expected exactly one listed attachment for {domain_arn} after reattach, got {matches}"
    )
    assert matches[0]["attachmentId"] == second_attachment_id, (
        f"listed attachmentId {matches[0]['attachmentId']!r} does not match the reattach "
        f"response's {second_attachment_id!r}"
    )
    assert matches[0]["status"] == "ATTACHED", (
        f"listed attachment status is {matches[0]['status']!r}, expected ATTACHED"
    )


def _domain_name(ctx, tag: str) -> str:
    return f"sim2real-{tag}-{uuid.uuid4().hex[:10]}"[:28]


def _app_name(ctx) -> str:
    return f"sim2real-app-{uuid.uuid4().hex[:10]}"[:30]


def _create_minimal_domain(ctx, name, *, instance_count: int = 1, instance_type: str = "t3.small.search") -> None:
    opensearch = ctx.client("opensearch")
    opensearch.create_domain(
        DomainName=name,
        EngineVersion="OpenSearch_2.11",
        ClusterConfig={
            "InstanceType": instance_type,
            "InstanceCount": instance_count,
            "DedicatedMasterEnabled": False,
            "ZoneAwarenessEnabled": False,
        },
        EBSOptions={"EBSEnabled": True, "VolumeType": "gp3", "VolumeSize": 10},
        TagList=[{"Key": "sim2real", "Value": "dsa"}],
    )
    ctx.on_cleanup(lambda: _delete_domain(ctx, name))


def _delete_domain(ctx, name) -> None:
    opensearch = ctx.client("opensearch")
    try:
        opensearch.delete_domain(DomainName=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _delete_application(ctx, app_id) -> None:
    opensearch = ctx.client("opensearch")
    try:
        opensearch.delete_application(id=app_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _detach(ctx, app_id, data_source_arn) -> None:
    opensearch = ctx.client("opensearch")
    try:
        opensearch.detach_data_source(id=app_id, dataSourceArn=data_source_arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _wait_domain_active(ctx, name, timeout_s: float = 1800.0, interval_s: float = 30.0):
    opensearch = ctx.client("opensearch")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        status = opensearch.describe_domain(DomainName=name)["DomainStatus"]
        if status.get("Created") and not status.get("Processing") and status.get("Endpoint"):
            return status
        time.sleep(interval_s)
    raise AssertionError(f"domain {name} did not become active within {timeout_s}s")


def _wait_application_active(ctx, app_id, timeout_s: float = 300.0, interval_s: float = 5.0) -> None:
    opensearch = ctx.client("opensearch")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        status = opensearch.get_application(id=app_id)["status"]
        if status == "ACTIVE":
            return
        if status == "FAILED":
            raise AssertionError(f"application {app_id} entered FAILED state")
        time.sleep(interval_s)
    raise AssertionError(f"application {app_id} did not become ACTIVE within {timeout_s}s")


def _wait_attachment_status(ctx, app_id, data_source_arn, want, timeout_s: float = 600.0, interval_s: float = 10.0):
    opensearch = ctx.client("opensearch")
    deadline = time.monotonic() + timeout_s
    last = None
    resp = None
    while time.monotonic() < deadline:
        resp = opensearch.describe_data_source_attachment(id=app_id, dataSourceArn=data_source_arn)
        last = resp["status"]
        if last == want:
            return resp
        if last == "FAILED":
            raise AssertionError(f"attachment for {data_source_arn} entered FAILED state")
        time.sleep(interval_s)
    raise AssertionError(f"attachment status never reached {want}, last={last}, resp={resp}")


def _wait_attachment_removed(ctx, app_id, data_source_arn, timeout_s: float = 300.0, interval_s: float = 10.0) -> None:
    opensearch = ctx.client("opensearch")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        code = None
        try:
            opensearch.describe_data_source_attachment(id=app_id, dataSourceArn=data_source_arn)
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
        if code == "ResourceNotFoundException":
            return
        time.sleep(interval_s)
    raise AssertionError(f"attachment for {data_source_arn} was never removed within {timeout_s}s")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
