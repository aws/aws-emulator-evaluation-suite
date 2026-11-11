"""ordering-data-source-attachment-listing-order."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "ordering-data-source-attachment-listing-order"
GROUP = "ordering"
SERVICES = ["opensearch"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListDataSourceAttachments returns the same attachment set on repeated calls, and attaching
    one more adds it while keeping the rest. No order is documented, so listings compare as sets."""
    aos = ctx.client("opensearch")
    app_id = _create_application(ctx, aos)

    # Kick off all domains up front so they provision concurrently -- domain
    # creation is the slow part, not the attach/list calls under test.
    domains = [_create_domain_async(ctx, aos, f"sim2real-ord{i}") for i in range(3)]

    attached_arns = []
    for _name, arn in domains:
        aos.attach_data_source(id=app_id, dataSourceArn=arn)
        status = _wait_attachment_status(ctx, aos, app_id, arn, "ATTACHED")
        assert status == "ATTACHED", f"attachment for {arn} entered {status}, not ATTACHED"
        attached_arns.append(arn)

    listing_a = _list_attachment_arns_in_order(aos, app_id)
    listing_b = _list_attachment_arns_in_order(aos, app_id)
    assert listing_a == listing_b or sorted(listing_a) == sorted(listing_b), (
        f"two consecutive ListDataSourceAttachments calls disagreed on order: {listing_a} vs {listing_b}"
    )
    assert set(listing_a) == set(attached_arns), f"listing {listing_a} missing/extra vs attached {attached_arns}"

    # Attach one more data source and confirm the original three are still listed.
    _extra_name, extra_arn = _create_domain_async(ctx, aos, "sim2real-ord-extra")
    aos.attach_data_source(id=app_id, dataSourceArn=extra_arn)
    status = _wait_attachment_status(ctx, aos, app_id, extra_arn, "ATTACHED")
    assert status == "ATTACHED", f"attachment for {extra_arn} entered {status}, not ATTACHED"

    listing_c = _list_attachment_arns_in_order(aos, app_id)
    assert set(listing_c) == set(attached_arns) | {extra_arn}, f"unexpected listing after append: {listing_c}"
    original_relative_order = [arn for arn in listing_c if arn in attached_arns]
    assert original_relative_order == listing_a or sorted(original_relative_order) == sorted(
        listing_a
    ), (
        f"appending a new attachment reshuffled the existing ones: {original_relative_order} != {listing_a}"
    )


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s, last value: {last}")


def _create_application(ctx, aos) -> str:
    raw = ctx.unique_name("sim2real-app-").lower()
    name = "".join(c for c in raw if c.isalnum() or c == "-")[:30].rstrip("-")
    if not name or not name[0].isalpha():
        name = "a" + name
    resp = aos.create_application(name=name[:30], tagList=[{"Key": "env", "Value": "test"}, {"Key": "team", "Value": "fidelity"}])
    app_id = resp["id"]
    ctx.on_cleanup(lambda: aos.delete_application(id=app_id))
    return app_id


def _compliant_domain_name(ctx, prefix: str) -> str:
    raw = ctx.unique_name(f"{prefix}-").lower()
    cleaned = "".join(c for c in raw if c.isalnum() or c == "-")
    cleaned = cleaned[:28].rstrip("-")
    if not cleaned or not cleaned[0].isalpha():
        cleaned = "d" + cleaned
    return cleaned[:28]


def _create_domain_async(ctx, aos, prefix: str):
    """AttachDataSource requires the dataSourceArn to be a real OpenSearch domain."""
    domain_name = _compliant_domain_name(ctx, prefix)
    resp = aos.create_domain(
        DomainName=domain_name,
        EngineVersion="OpenSearch_2.11",
        ClusterConfig={
            "InstanceType": "t3.small.search",
            "InstanceCount": 1,
            "DedicatedMasterEnabled": False,
            "ZoneAwarenessEnabled": False,
        },
        EBSOptions={"EBSEnabled": True, "VolumeType": "gp3", "VolumeSize": 10},
        TagList=[{"Key": "env", "Value": "test"}, {"Key": "team", "Value": "fidelity"}],
    )
    domain_arn = resp["DomainStatus"]["ARN"]
    ctx.on_cleanup(lambda: aos.delete_domain(DomainName=domain_name))
    return domain_name, domain_arn


def _wait_attachment_status(ctx, aos, app_id: str, data_source_arn: str, want: str, timeout_s: float = 1800.0) -> str:
    def _status() -> str:
        return aos.describe_data_source_attachment(id=app_id, dataSourceArn=data_source_arn)["status"]

    return _poll_until(_status, lambda s: s in (want, "FAILED"), timeout_s=timeout_s, interval_s=15)


def _list_attachment_arns_in_order(aos, app_id: str) -> list:
    arns: list = []
    next_token = None
    while True:
        kwargs = {"id": app_id}
        if next_token:
            kwargs["nextToken"] = next_token
        resp = aos.list_data_source_attachments(**kwargs)
        for attachment in resp.get("attachments", []):
            arns.append(attachment["dataSourceArn"])
        next_token = resp.get("nextToken")
        if not next_token:
            break
    return arns


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
