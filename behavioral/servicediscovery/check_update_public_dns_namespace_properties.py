"""update-public-dns-namespace-properties."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-public-dns-namespace-properties"
GROUP = "state-machine"
SERVICES = ["servicediscovery"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdatePublicDnsNamespace mutates the namespace's Description in place and the
    change is reflected on GetNamespace, without disturbing a service already
    associated with the namespace."""
    sd = ctx.client("servicediscovery")
    name = f"{ctx.unique_name('sim2real-pubns-')}.com"

    create_op_id = sd.create_public_dns_namespace(
        Name=name, Description="original description"
    )["OperationId"]
    op = _poll_operation(ctx, sd, create_op_id, timeout_s=180.0)
    assert op["Status"] == "SUCCESS", f"create failed: {op.get('ErrorMessage')}"
    ns_id = op["Targets"]["NAMESPACE"]
    ctx.on_cleanup(lambda: _safe_delete_namespace(sd, ns_id))

    svc = sd.create_service(
        Name=ctx.unique_name("sim2real-svc-"),
        NamespaceId=ns_id,
        DnsConfig={"DnsRecords": [{"Type": "A", "TTL": 60}], "RoutingPolicy": "WEIGHTED"},
    )["Service"]
    svc_id = svc["Id"]
    ctx.on_cleanup(lambda: _safe_delete_service(sd, svc_id))

    # Confirm the service is visible under the namespace before mutating the
    # namespace's own properties (baseline for the "unaffected" assertion).
    before_ids = _poll_service_visible(sd, ns_id, svc_id, timeout_s=120.0)
    assert svc_id in before_ids, f"service {svc_id} not visible under namespace before update: {before_ids}"
    before_ns = sd.get_namespace(Id=ns_id)["Namespace"]
    assert before_ns["Description"] == "original description", (
        f"expected pre-update Description to be 'original description', got {before_ns.get('Description')!r}"
    )

    update_op_id = sd.update_public_dns_namespace(
        Id=ns_id, Namespace={"Description": "updated description"}
    )["OperationId"]
    update_op = _poll_operation(ctx, sd, update_op_id, timeout_s=180.0)
    assert update_op["Status"] == "SUCCESS", f"update failed: {update_op.get('ErrorMessage')}"

    after_ns = sd.get_namespace(Id=ns_id)["Namespace"]
    assert after_ns["Id"] == before_ns["Id"], (
        f"namespace Id must not change on update: before={before_ns['Id']!r} after={after_ns['Id']!r}"
    )
    assert after_ns["Description"] == "updated description", (
        f"expected updated Description to be reflected, got {after_ns.get('Description')!r}"
    )

    after_ids = sd.list_services(
        Filters=[{"Name": "NAMESPACE_ID", "Values": [ns_id], "Condition": "EQ"}]
    )
    after_ids = [s["Id"] for s in after_ids["Services"]]
    assert svc_id in after_ids, "service association must survive the namespace update"

    after_svc = sd.get_service(Id=svc_id)["Service"]
    assert after_svc["Name"] == svc["Name"], (
        f"service Name must be unaffected by namespace update: before={svc['Name']!r} after={after_svc['Name']!r}"
    )
    assert after_svc["DnsConfig"] == svc["DnsConfig"], (
        f"service DnsConfig must be unaffected by namespace update: before={svc['DnsConfig']!r} "
        f"after={after_svc['DnsConfig']!r}"
    )


def _poll_service_visible(sd, ns_id, svc_id, timeout_s=120.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    ids = []
    while time.monotonic() < deadline:
        resp = sd.list_services(
            Filters=[{"Name": "NAMESPACE_ID", "Values": [ns_id], "Condition": "EQ"}]
        )
        ids = [s["Id"] for s in resp["Services"]]
        if svc_id in ids:
            return ids
        time.sleep(interval_s)
    raise AssertionError(
        f"service {svc_id} not visible under namespace {ns_id} within {timeout_s}s "
        f"(last list={ids})"
    )


def _poll_operation(ctx, sd, operation_id, timeout_s=180.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    op = None
    while time.monotonic() < deadline:
        op = sd.get_operation(OperationId=operation_id)["Operation"]
        if op["Status"] in ("SUCCESS", "FAIL"):
            return op
        time.sleep(interval_s)
    raise AssertionError(
        f"operation {operation_id} did not reach a terminal state within {timeout_s}s "
        f"(last status={op['Status'] if op else None})"
    )


def _safe_delete_namespace(sd, ns_id):
    if not ns_id:
        return
    try:
        sd.delete_namespace(Id=ns_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NamespaceNotFound":
            raise


def _safe_delete_service(sd, svc_id):
    try:
        sd.delete_service(Id=svc_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ServiceNotFound":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
