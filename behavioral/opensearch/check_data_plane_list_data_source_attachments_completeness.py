"""data-plane-list-data-source-attachments-completeness."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "data-plane-list-data-source-attachments-completeness"
GROUP = "data-plane"
SERVICES = ["opensearch"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListDataSourceAttachments reflects exactly the current attached set after
    N attaches and a partial detach -- no stale or missing entries."""
    aos = ctx.client("opensearch")
    app_id = _create_application(ctx, aos)

    # Kick off both domains up front so they provision concurrently.
    domains = [_create_domain_async(ctx, aos, f"sim2real-comp{i}") for i in range(2)]
    domain_arns = [arn for _name, arn in domains]

    for arn in domain_arns:
        aos.attach_data_source(id=app_id, dataSourceArn=arn)
        status = _wait_attachment_status(ctx, aos, app_id, arn, "ATTACHED")
        assert status == "ATTACHED", f"attachment for {arn} entered {status}, not ATTACHED"

    attached = _list_attachment_arns(aos, app_id)
    assert attached == set(domain_arns), f"expected {set(domain_arns)}, got {attached}"

    detached_arn = domain_arns[0]
    aos.detach_data_source(id=app_id, dataSourceArn=detached_arn)

    def _detached() -> set:
        return _list_attachment_arns(aos, app_id)

    remaining = _poll_until(
        _detached,
        lambda s: detached_arn not in s,
        timeout_s=180,
        interval_s=5,
    )
    expected_remaining = set(domain_arns) - {detached_arn}
    assert remaining == expected_remaining, f"expected {expected_remaining}, got {remaining}"


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
    resp = aos.create_application(name=name[:30], tagList=[{"Key": "sim2real", "Value": name[:30]}])
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
        TagList=[{"Key": "sim2real", "Value": domain_name}],
    )
    domain_arn = resp["DomainStatus"]["ARN"]
    ctx.on_cleanup(lambda: aos.delete_domain(DomainName=domain_name))
    return domain_name, domain_arn


def _wait_attachment_status(ctx, aos, app_id: str, data_source_arn: str, want: str, timeout_s: float = 1800.0) -> str:
    def _status() -> str:
        return aos.describe_data_source_attachment(id=app_id, dataSourceArn=data_source_arn)["status"]

    return _poll_until(_status, lambda s: s in (want, "FAILED"), timeout_s=timeout_s, interval_s=15)


def _list_attachment_arns(aos, app_id: str) -> set[str]:
    arns: set[str] = set()
    next_token = None
    while True:
        kwargs = {"id": app_id}
        if next_token:
            kwargs["nextToken"] = next_token
        resp = aos.list_data_source_attachments(**kwargs)
        for attachment in resp.get("attachments", []):
            arns.add(attachment["dataSourceArn"])
        next_token = resp.get("nextToken")
        if not next_token:
            break
    return arns


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
