"""concurrent-update-service-attributes-last-writer-wins."""
from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "concurrent-update-service-attributes-last-writer-wins"
GROUP = "concurrency"
SERVICES = ["servicediscovery"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Concurrent UpdateServiceAttributes calls on the same service converge to a
    single, uncorrupted value per contended key (no interleaved partial merge),
    while distinct keys written by different racers are both preserved."""
    sd = ctx.client("servicediscovery")
    name = f"{ctx.unique_name('sim2real-pubns-')}.com"

    create_op_id = sd.create_public_dns_namespace(
        Name=name, Tags=[{"Key": "sim2real-audit", "Value": "true"}]
    )["OperationId"]
    op = _poll_operation(ctx, sd, create_op_id, timeout_s=180.0)
    assert op["Status"] == "SUCCESS", f"namespace create failed: {op.get('ErrorMessage')}"
    ns_id = op["Targets"]["NAMESPACE"]
    ctx.on_cleanup(lambda: _safe_delete_namespace(sd, ns_id))

    svc = sd.create_service(
        Name=ctx.unique_name("sim2real-svc-"),
        NamespaceId=ns_id,
        DnsConfig={"DnsRecords": [{"Type": "A", "TTL": 60}], "RoutingPolicy": "WEIGHTED"},
        Tags=[{"Key": "sim2real-audit", "Value": "true"}],
    )["Service"]
    svc_id = svc["Id"]
    ctx.on_cleanup(lambda: _safe_delete_service(sd, svc_id))

    def _writer_1():
        sd.update_service_attributes(
            ServiceId=svc_id, Attributes={"shared": "from-writer-1", "onlyA": "vA"}
        )

    def _writer_2():
        sd.update_service_attributes(
            ServiceId=svc_id, Attributes={"shared": "from-writer-2", "onlyB": "vB"}
        )

    with ThreadPoolExecutor(max_workers=2) as pool:
        f1 = pool.submit(_writer_1)
        f2 = pool.submit(_writer_2)
        f1.result()
        f2.result()

    attrs = sd.get_service_attributes(ServiceId=svc_id)["ServiceAttributes"]["Attributes"]
    assert attrs["onlyA"] == "vA", attrs
    assert attrs["onlyB"] == "vB", attrs
    assert attrs["shared"] in ("from-writer-1", "from-writer-2"), attrs

    again = sd.get_service_attributes(ServiceId=svc_id)["ServiceAttributes"]["Attributes"]
    assert again == attrs, f"contended value must be stable across independent reads: {attrs!r} != {again!r}"


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
