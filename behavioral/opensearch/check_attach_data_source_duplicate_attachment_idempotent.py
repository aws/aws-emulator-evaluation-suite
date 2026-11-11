"""attach-data-source-duplicate-attachment-idempotent."""
from __future__ import annotations

import time
from typing import Any

from behavioral_harness import tags

CHECK = "attach-data-source-duplicate-attachment-idempotent"
GROUP = "negative-classes"
SERVICES = ["opensearch"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A repeat AttachDataSource for an ATTACHED data source returns the same attachmentId with status
    ATTACHED, and ListDataSourceAttachments still holds exactly one record for the domain ARN.
    """
    client = ctx.client("opensearch")
    domain_name = _domain_name(ctx, "att")
    _create_minimal_domain(ctx, client, domain_name)
    domain_arn = _wait_domain_active(ctx, client, domain_name)["ARN"]

    app_name = _app_name(ctx, "att")
    app_id = _create_application(ctx, client, app_name)
    _wait_application_active(ctx, client, app_id)

    first = client.attach_data_source(id=app_id, dataSourceArn=domain_arn)
    attachment_id_1 = first["attachmentId"]
    _wait_attachment_status(ctx, client, app_id, domain_arn, {"ATTACHED"})

    second = client.attach_data_source(id=app_id, dataSourceArn=domain_arn)
    attachment_id_2 = second["attachmentId"]

    assert attachment_id_1 == attachment_id_2, (
        f"duplicate AttachDataSource created a new attachment "
        f"({attachment_id_1!r} != {attachment_id_2!r}) instead of returning the existing one"
    )
    assert second["status"] == "ATTACHED", (
        f"expected repeat AttachDataSource to report status ATTACHED, got {second['status']!r}"
    )

    attachments = client.list_data_source_attachments(id=app_id)["attachments"]
    matching = [a for a in attachments if a["dataSourceArn"] == domain_arn]
    assert len(matching) == 1, f"expected exactly one attachment record, found {len(matching)}"


def _domain_name(ctx: Any, tag: str) -> str:
    return ctx.unique_name(f"sim2real-{tag}-")[:28].rstrip("-")


def _app_name(ctx: Any, tag: str) -> str:
    return ctx.unique_name(f"sim2real-app{tag}-")[:30].rstrip("-")


def _create_minimal_domain(ctx: Any, client: Any, domain_name: str) -> None:
    client.create_domain(
        DomainName=domain_name,
        ClusterConfig={
            "InstanceType": "t3.small.search",
            "InstanceCount": 1,
            "DedicatedMasterEnabled": False,
            "ZoneAwarenessEnabled": False,
        },
        EBSOptions={"EBSEnabled": True, "VolumeType": "gp3", "VolumeSize": 10},
        TagList=[{"Key": "sim2real", "Value": "attach-data-source-duplicate-attachment-idempotent"}],
    )
    ctx.on_cleanup(lambda: _delete_domain_and_wait(ctx, client, domain_name))


def _delete_domain_and_wait(ctx: Any, client: Any, domain_name: str) -> None:
    try:
        client.delete_domain(DomainName=domain_name)
    except Exception as exc:  # pragma: no cover - already gone
        if _error_code_from_exc(exc) != "ResourceNotFoundException":
            raise
        return
    deadline = time.monotonic() + 1200
    while time.monotonic() < deadline:
        try:
            client.describe_domain(DomainName=domain_name)
        except Exception as exc:
            if _error_code_from_exc(exc) == "ResourceNotFoundException":
                return
            raise
        time.sleep(20)


def _wait_domain_active(ctx: Any, client: Any, domain_name: str, timeout_s: float = 1200.0) -> dict:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        status = client.describe_domain(DomainName=domain_name)["DomainStatus"]
        last = status
        if status.get("Created") and not status.get("Processing") and status.get("Endpoint"):
            return status
        time.sleep(2)
    raise AssertionError(f"domain {domain_name} never became active: {last}")


def _create_application(ctx: Any, client: Any, app_name: str) -> str:
    resp = client.create_application(
        name=app_name,
        tagList=[{"Key": "sim2real", "Value": "attach-data-source-duplicate-attachment-idempotent"}],
    )
    app_id = resp["id"]
    ctx.on_cleanup(lambda: client.delete_application(id=app_id))
    return app_id


def _wait_application_active(ctx: Any, client: Any, app_id: str, timeout_s: float = 120.0) -> None:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        status = client.get_application(id=app_id)["status"]
        last = status
        if status == "ACTIVE":
            return
        time.sleep(3)
    raise AssertionError(f"application {app_id} never became ACTIVE: {last}")


def _wait_attachment_status(
    ctx: Any, client: Any, app_id: str, data_source_arn: str, terminal: set, timeout_s: float = 120.0
) -> str:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        status = client.describe_data_source_attachment(id=app_id, dataSourceArn=data_source_arn)["status"]
        last = status
        if status in terminal:
            return status
        time.sleep(3)
    raise AssertionError(f"attachment for {data_source_arn} never reached {terminal}: {last}")


def _error_code_from_exc(exc: Exception) -> str | None:
    response = getattr(exc, "response", None)
    if not response:
        return None
    return response.get("Error", {}).get("Code")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
