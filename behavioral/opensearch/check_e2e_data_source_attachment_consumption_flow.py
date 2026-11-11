"""e2e-data-source-attachment-consumption-flow."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "e2e-data-source-attachment-consumption-flow"
GROUP = "e2e"
SERVICES = ["opensearch"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """An attached domain is ATTACHED in DescribeDataSourceAttachment and ListDataSourceAttachments; after
    DetachDataSource it is gone from the listing and describing it fails with ResourceNotFoundException.
    """
    opensearch = ctx.client("opensearch")

    ds_arn = _create_minimal_domain(ctx)
    app_id = _create_application(ctx)

    attach_resp = opensearch.attach_data_source(id=app_id, dataSourceArn=ds_arn)
    assert attach_resp["dataSourceArn"] == ds_arn

    attached = _wait_attachment_status(ctx, app_id, ds_arn, timeout_s=300.0)
    assert attached["status"] == "ATTACHED"
    assert attached["dataSourceArn"] == ds_arn

    described = opensearch.describe_data_source_attachment(id=app_id, dataSourceArn=ds_arn)
    assert described["dataSourceArn"] == ds_arn
    assert described["status"] == "ATTACHED"

    listing = opensearch.list_data_source_attachments(id=app_id)["attachments"]
    assert any(a["dataSourceArn"] == ds_arn and a["status"] == "ATTACHED" for a in listing)

    opensearch.detach_data_source(id=app_id, dataSourceArn=ds_arn)

    remaining = _wait_attachment_absent(ctx, app_id, ds_arn, timeout_s=180.0)
    assert not any(a["dataSourceArn"] == ds_arn for a in remaining)

    detached_code, detached_message = _error(
        lambda: opensearch.describe_data_source_attachment(id=app_id, dataSourceArn=ds_arn)
    )
    assert detached_code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException describing a detached attachment, got {detached_code!r}"
    )
    expected = f"Data source attachment not found for application {app_id} and data source {ds_arn}"
    assert detached_message == expected, f"expected message {expected!r}, got {detached_message!r}"


def _create_application(ctx) -> str:
    opensearch = ctx.client("opensearch")
    raw = ctx.unique_name("sim2real-app-").lower()
    name = "".join(c for c in raw if c.isalnum() or c == "-")[:30].rstrip("-")
    if not name or not name[0].isalpha():
        name = "a" + name
    resp = opensearch.create_application(
        name=name[:30], tagList=[{"Key": "sim2real", "Value": "audit"}]
    )
    app_id = resp["id"]
    ctx.on_cleanup(lambda: opensearch.delete_application(id=app_id))
    return app_id


def _compliant_domain_name(ctx, prefix: str) -> str:
    raw = ctx.unique_name(f"{prefix}-").lower()
    cleaned = "".join(c for c in raw if c.isalnum() or c == "-")
    cleaned = cleaned[:28].rstrip("-")
    if not cleaned or not cleaned[0].isalpha():
        cleaned = "d" + cleaned
    return cleaned[:28]


def _create_minimal_domain(ctx) -> str:
    opensearch = ctx.client("opensearch")
    domain_name = _compliant_domain_name(ctx, "dsdom")
    resp = opensearch.create_domain(
        DomainName=domain_name,
        EngineVersion="OpenSearch_2.11",
        ClusterConfig={
            "InstanceType": "t3.small.search",
            "InstanceCount": 1,
            "DedicatedMasterEnabled": False,
            "ZoneAwarenessEnabled": False,
        },
        EBSOptions={"EBSEnabled": True, "VolumeType": "gp3", "VolumeSize": 10},
        TagList=[{"Key": "sim2real", "Value": "audit"}],
    )
    domain_arn = resp["DomainStatus"]["ARN"]
    ctx.on_cleanup(lambda: opensearch.delete_domain(DomainName=domain_name))
    _wait_domain_active(ctx, domain_name, timeout_s=1500.0)
    return domain_arn


def _wait_domain_active(ctx, domain_name: str, timeout_s: float = 1500.0, interval_s: float = 30.0):
    opensearch = ctx.client("opensearch")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = opensearch.describe_domain(DomainName=domain_name)["DomainStatus"]
        if last["Created"] and not last["Processing"]:
            return last
        time.sleep(interval_s)
    raise AssertionError(f"domain {domain_name} did not reach ACTIVE in {timeout_s}s; last={last}")


def _wait_attachment_status(ctx, app_id: str, ds_arn: str, timeout_s: float = 180.0, interval_s: float = 5.0):
    opensearch = ctx.client("opensearch")
    terminal = {"ATTACHED", "FAILED"}
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = opensearch.describe_data_source_attachment(id=app_id, dataSourceArn=ds_arn)
        if last["status"] in terminal:
            return last
        time.sleep(interval_s)
    raise AssertionError(f"attachment for {ds_arn} never reached a terminal status; last={last}")


def _error(fn):
    """(code, message) of the ClientError fn() raises; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as err:
        error = err.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError(f"expected the call to fail, but it succeeded: {result!r}")


def _wait_attachment_absent(ctx, app_id: str, ds_arn: str, timeout_s: float = 180.0, interval_s: float = 5.0):
    opensearch = ctx.client("opensearch")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = opensearch.list_data_source_attachments(id=app_id)["attachments"]
        if not any(a["dataSourceArn"] == ds_arn for a in last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"attachment for {ds_arn} was never removed from listings; last={last}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
