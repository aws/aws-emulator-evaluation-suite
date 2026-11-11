"""attach-data-source-accepts-nonexistent-arn-without-attaching."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "attach-data-source-accepts-nonexistent-arn-without-attaching"
GROUP = "overly-permissive"
SERVICES = ["opensearch"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "plane:control")
def run(ctx) -> None:
    """AttachDataSource accepts a valid-looking ARN of a nonexistent domain as PENDING, but it
    never reaches ATTACHED (stays PENDING or turns FAILED), while attaching a real ACTIVE domain
    does reach ATTACHED, proving the attachment flow works at all."""
    opensearch = ctx.client("opensearch")
    app_id = _create_application(ctx)

    account_id = ctx.client("sts").get_caller_identity()["Account"]
    bogus_domain = ctx.unique_name("sim2real-nope-").lower().replace("_", "-")[:28]
    bogus_arn = f"arn:aws:es:{ctx.region}:{account_id}:domain/{bogus_domain}"

    # Start the slow control domain now so its provisioning overlaps the bogus-ARN poll.
    real_domain_name, real_domain_arn = _create_domain_no_wait(ctx)

    attach_resp = opensearch.attach_data_source(id=app_id, dataSourceArn=bogus_arn)
    assert attach_resp["status"] in {"PENDING", "FAILED"}, (
        f"expected PENDING or FAILED attaching a nonexistent-domain ARN, got {attach_resp['status']!r}"
    )

    # A bogus attachment may stay PENDING indefinitely, so the wait is bounded.
    final_status = _poll_status_never_attached(ctx, app_id, bogus_arn, timeout_s=180.0)
    assert final_status in {"PENDING", "FAILED"}, f"unexpected status {final_status}"

    listing = opensearch.list_data_source_attachments(id=app_id)["attachments"]
    assert not any(a["dataSourceArn"] == bogus_arn and a["status"] == "ATTACHED" for a in listing), (
        f"bogus ARN {bogus_arn} shows ATTACHED in ListDataSourceAttachments: {listing!r}"
    )

    # Control: without it, a target that never attaches anything would pass the above.
    _wait_domain_active(ctx, real_domain_name, timeout_s=1500.0)
    real_attach = opensearch.attach_data_source(id=app_id, dataSourceArn=real_domain_arn)
    assert real_attach["status"] in {"PENDING", "ATTACHED"}, (
        f"unexpected initial status attaching a real ACTIVE domain: {real_attach['status']!r}"
    )
    real_final = _poll_status_until(
        ctx, app_id, real_domain_arn, terminal={"ATTACHED", "FAILED"}, timeout_s=300.0
    )
    assert real_final == "ATTACHED", (
        f"attaching a real, ACTIVE domain settled into {real_final!r} instead of ATTACHED"
    )


def _create_application(ctx) -> str:
    opensearch = ctx.client("opensearch")
    raw = ctx.unique_name("sim2real-appneg-").lower()
    name = "".join(c for c in raw if c.isalnum() or c == "-")[:30].rstrip("-")
    if not name or not name[0].isalpha():
        name = "a" + name
    resp = opensearch.create_application(
        name=name[:30], tagList=[{"Key": "sim2real", "Value": CHECK}]
    )
    app_id = resp["id"]
    ctx.on_cleanup(lambda: opensearch.delete_application(id=app_id))
    return app_id


def _create_domain_no_wait(ctx) -> tuple[str, str]:
    opensearch = ctx.client("opensearch")
    raw = ctx.unique_name("sim2real-nreal-").lower()
    domain_name = "".join(c for c in raw if c.isalnum() or c == "-")[:28].rstrip("-")
    resp = opensearch.create_domain(
        DomainName=domain_name,
        # A pinned engine version provisions faster than the default.
        EngineVersion="OpenSearch_2.13",
        ClusterConfig={
            "InstanceType": "t3.small.search",
            "InstanceCount": 1,
            "DedicatedMasterEnabled": False,
            "ZoneAwarenessEnabled": False,
        },
        EBSOptions={"EBSEnabled": True, "VolumeType": "gp3", "VolumeSize": 10},
        TagList=[{"Key": "sim2real", "Value": CHECK}],
    )
    domain_arn = resp["DomainStatus"]["ARN"]
    ctx.on_cleanup(lambda: opensearch.delete_domain(DomainName=domain_name))
    return domain_name, domain_arn


def _wait_domain_active(ctx, domain_name: str, timeout_s: float = 1500.0, interval_s: float = 15.0) -> None:
    opensearch = ctx.client("opensearch")
    deadline = time.monotonic() + timeout_s
    last_state = None
    while time.monotonic() < deadline:
        status = opensearch.describe_domain(DomainName=domain_name)["DomainStatus"]
        last_state = "PROCESSING" if status.get("Processing") else "ACTIVE"
        if not status.get("Processing") and not status.get("UpgradeProcessing"):
            return
        time.sleep(interval_s)
    raise AssertionError(f"domain {domain_name} never became ACTIVE within {timeout_s}s (last={last_state!r})")


def _poll_status_never_attached(ctx, app_id: str, ds_arn: str, timeout_s: float = 180.0, interval_s: float = 5.0) -> str:
    opensearch = ctx.client("opensearch")
    deadline = time.monotonic() + timeout_s
    last_status = "PENDING"
    while time.monotonic() < deadline:
        last_status = opensearch.describe_data_source_attachment(id=app_id, dataSourceArn=ds_arn)["status"]
        assert last_status != "ATTACHED", "attachment to a nonexistent domain became ATTACHED"
        if last_status == "FAILED":
            return last_status
        time.sleep(interval_s)
    return last_status


def _poll_status_until(ctx, app_id: str, ds_arn: str, terminal: set[str], timeout_s: float, interval_s: float = 10.0) -> str:
    opensearch = ctx.client("opensearch")
    deadline = time.monotonic() + timeout_s
    last_status = "PENDING"
    while time.monotonic() < deadline:
        last_status = opensearch.describe_data_source_attachment(id=app_id, dataSourceArn=ds_arn)["status"]
        if last_status in terminal:
            return last_status
        time.sleep(interval_s)
    return last_status


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
