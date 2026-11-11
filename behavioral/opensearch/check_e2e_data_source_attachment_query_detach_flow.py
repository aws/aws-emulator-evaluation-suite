"""e2e-data-source-attachment-query-detach-flow."""
from __future__ import annotations

import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "e2e-data-source-attachment-query-detach-flow"
GROUP = "e2e"
SERVICES = ["opensearch"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Attaching a domain as an application data source makes it queryable via
    Describe/ListDataSourceAttachments, and detaching removes it from both views."""
    opensearch = ctx.client("opensearch")
    domain_name = _short_name(ctx.unique_name("aosdxd"), 28)
    domain_arn = _create_domain(ctx, opensearch, domain_name)

    app_name = _short_name(ctx.unique_name("aosappd"), 30)
    try:
        app = opensearch.create_application(name=app_name)
    except ClientError as err:
        if err.response["Error"]["Code"] == "DisabledOperationException":
            raise AssertionError(
                "OpenSearch Applications feature is not enabled for this account/region"
            )
        raise
    app_id = app["id"]
    ctx.on_cleanup(lambda: _delete_application(ctx, app_id))
    _wait_application_active(opensearch, app_id)

    attach = opensearch.attach_data_source(id=app_id, dataSourceArn=domain_arn)
    attachment_id = attach["attachmentId"]

    final_status = _poll_until(
        lambda: opensearch.describe_data_source_attachment(id=app_id, dataSourceArn=domain_arn)["status"],
        predicate=lambda s: s in ("ATTACHED", "FAILED"),
        timeout_s=180.0,
        interval_s=5.0,
    )
    assert final_status == "ATTACHED", f"data source attachment ended in status {final_status!r}"

    listed = opensearch.list_data_source_attachments(id=app_id)["attachments"]
    matches = [a for a in listed if a["dataSourceArn"] == domain_arn]
    assert len(matches) == 1, f"expected exactly one attachment for {domain_arn}, found {len(matches)}"
    assert matches[0]["attachmentId"] == attachment_id, (
        f"expected attachmentId {attachment_id!r}, got {matches[0]['attachmentId']!r}"
    )
    assert matches[0]["status"] == "ATTACHED", f"expected status ATTACHED, got {matches[0]['status']!r}"

    opensearch.detach_data_source(id=app_id, dataSourceArn=domain_arn)

    def _gone() -> bool:
        listed_now = opensearch.list_data_source_attachments(id=app_id)["attachments"]
        return not any(a["dataSourceArn"] == domain_arn for a in listed_now)

    _poll_until(_gone, predicate=lambda ok: ok, timeout_s=120.0, interval_s=5.0)

    code, message = _error(
        lambda: opensearch.describe_data_source_attachment(id=app_id, dataSourceArn=domain_arn)
    )
    assert code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException for a describe on a detached data source, got {code!r}"
    )
    expected = f"Data source attachment not found for application {app_id} and data source {domain_arn}"
    assert message == expected, f"expected message {expected!r}, got {message!r}"


def _short_name(raw: str, max_len: int, min_len: int = 3) -> str:
    name = "".join(c for c in raw.lower() if c.isalnum() or c == "-")
    if len(name) > max_len:
        name = name[:max_len]
    name = name.rstrip("-")
    if not name or not name[0].isalpha():
        name = "a" + name[1:]
    while len(name) < min_len:
        name += "0"
    return name


def _error(fn) -> tuple:
    """(code, message) of the ClientError fn() raises; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected the call to fail, but it succeeded: {result!r}")


def _poll_until(probe, predicate, timeout_s: float, interval_s: float) -> Any:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition never met within {timeout_s}s; last value={last!r}")


def _delete_application(ctx, app_id: str) -> None:
    opensearch = ctx.client("opensearch")
    try:
        opensearch.delete_application(id=app_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _wait_application_active(opensearch, app_id: str, timeout_s: float = 120.0) -> None:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        status = opensearch.get_application(id=app_id)["status"]
        if status == "ACTIVE":
            return
        if status == "FAILED":
            raise AssertionError(f"application {app_id} entered FAILED state")
        time.sleep(5)
    raise AssertionError(f"application {app_id} never became ACTIVE within {timeout_s}s")


def _create_domain(ctx, opensearch, domain_name: str, timeout_s: float = 1800.0) -> str:
    opensearch.create_domain(
        DomainName=domain_name,
        ClusterConfig={
            "InstanceType": "t3.small.search",
            "InstanceCount": 1,
            "DedicatedMasterEnabled": False,
            "ZoneAwarenessEnabled": False,
        },
        EBSOptions={"EBSEnabled": True, "VolumeType": "gp3", "VolumeSize": 10},
    )

    def _delete() -> None:
        try:
            opensearch.delete_domain(DomainName=domain_name)
        except ClientError as err:
            if err.response["Error"]["Code"] != "ResourceNotFoundException":
                raise

    ctx.on_cleanup(_delete)
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        status = opensearch.describe_domain(DomainName=domain_name)["DomainStatus"]
        if status.get("Created") and not status.get("Processing") and status.get("Endpoint"):
            return status["ARN"]
        time.sleep(2)
    raise AssertionError(f"domain {domain_name} never became active within {timeout_s}s")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
