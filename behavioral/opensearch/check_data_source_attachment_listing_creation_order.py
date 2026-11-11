"""data-source-attachment-listing-creation-order."""
from __future__ import annotations

import time
import uuid
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "data-source-attachment-listing-creation-order"
GROUP = "ordering"
SERVICES = ["opensearch"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListDataSourceAttachments returns attachments in a stable order across
    repeated calls after multiple AttachDataSource operations on the same
    OpenSearch application.
    """
    opensearch = ctx.client("opensearch")

    app_name = _short_name("sim2real-app", 30)
    app = opensearch.create_application(
        name=app_name, tagList=[{"Key": "sim2real-check", "Value": CHECK}]
    )
    app_id = app["id"]
    ctx.on_cleanup(lambda: _delete_application(opensearch, app_id))

    domain1 = _short_name("sim2real-d1", 28)
    domain2 = _short_name("sim2real-d2", 28)
    arn1 = _create_minimal_domain(ctx, opensearch, domain1)
    arn2 = _create_minimal_domain(ctx, opensearch, domain2)

    attach1 = opensearch.attach_data_source(id=app_id, dataSourceArn=arn1)
    attach2 = opensearch.attach_data_source(id=app_id, dataSourceArn=arn2)
    ctx.on_cleanup(lambda: _detach_quiet(opensearch, app_id, arn2))
    ctx.on_cleanup(lambda: _detach_quiet(opensearch, app_id, arn1))

    assert attach1["attachmentId"] != attach2["attachmentId"], (
        f"two distinct AttachDataSource calls must not reuse an attachmentId: "
        f"{attach1['attachmentId']!r} == {attach2['attachmentId']!r}"
    )

    listing_1 = opensearch.list_data_source_attachments(id=app_id)["attachments"]
    listing_2 = opensearch.list_data_source_attachments(id=app_id)["attachments"]

    order_1 = [a["attachmentId"] for a in listing_1]
    order_2 = [a["attachmentId"] for a in listing_2]

    assert {attach1["attachmentId"], attach2["attachmentId"]} <= set(order_1), (
        "both attachments must appear in the listing"
    )
    # the defining behavioral contract: repeated calls return the identical order
    assert order_1 == order_2, f"ListDataSourceAttachments order was not stable across calls: {order_1} != {order_2}"


# ===== shared domain helpers =====


def _short_name(prefix: str, maxlen: int) -> str:
    suffix = uuid.uuid4().hex[:8]
    return f"{prefix}{suffix}"[:maxlen]


def _create_minimal_domain(ctx: Any, opensearch: Any, name: str) -> str:
    resp = opensearch.create_domain(
        DomainName=name,
        EngineVersion="OpenSearch_2.11",
        ClusterConfig={
            "InstanceType": "t3.small.search",
            "InstanceCount": 1,
            "DedicatedMasterEnabled": False,
            "ZoneAwarenessEnabled": False,
        },
        EBSOptions={"EBSEnabled": True, "VolumeType": "gp3", "VolumeSize": 10},
        TagList=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _delete_domain_when_ready(opensearch, name))
    return resp["DomainStatus"]["ARN"]


def _delete_domain_when_ready(opensearch: Any, name: str, timeout_s: float = 600.0, interval_s: float = 2.0) -> None:
    """Delete the domain: return if it is gone, retry a refusal while a change is still in
    progress to the deadline, raise anything else."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            opensearch.delete_domain(DomainName=name)
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "ResourceNotFoundException":
                return
            if code not in ("ConflictException", "ValidationException") or time.monotonic() >= deadline:
                raise
        time.sleep(interval_s)


def _delete_application(opensearch: Any, app_id: str) -> None:
    try:
        opensearch.delete_application(id=app_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _detach_quiet(opensearch: Any, app_id: str, data_source_arn: str) -> None:
    try:
        opensearch.detach_data_source(id=app_id, dataSourceArn=data_source_arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
