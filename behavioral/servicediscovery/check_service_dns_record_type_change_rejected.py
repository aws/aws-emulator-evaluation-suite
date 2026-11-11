"""service-dns-record-type-change-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "service-dns-record-type-change-rejected"
GROUP = "representation"
SERVICES = ["servicediscovery"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateService cannot change a DnsConfig record's Type; the record type is immutable once the service is created."""
    sd = ctx.client("servicediscovery")

    ns_resp = sd.create_public_dns_namespace(Name=ctx.unique_name("simparity-sd-") + ".test")
    ns_op = _wait_operation(sd, ns_resp["OperationId"])
    ns_id = ns_op["Targets"]["NAMESPACE"]
    ctx.on_cleanup(lambda: _delete_namespace_best_effort(sd, ns_id))

    svc = sd.create_service(
        Name=ctx.unique_name("simparity-sd-svc-"),
        NamespaceId=ns_id,
        DnsConfig={"DnsRecords": [{"Type": "A", "TTL": 60}], "RoutingPolicy": "WEIGHTED"},
    )["Service"]
    svc_id = svc["Id"]
    ctx.on_cleanup(lambda: _delete_service_best_effort(sd, svc_id))

    error = _client_error(
        lambda: sd.update_service(
            Id=svc_id,
            Service={"DnsConfig": {"DnsRecords": [{"Type": "CNAME", "TTL": 60}]}},
        )
    )
    assert error.get("Code") == "InvalidInput", f"expected InvalidInput for a DnsConfig record Type change, got {error!r}"
    expected_message = (
        "The record types in the request must be the same as those present in the existing service. "
        "Records in the existing service are [A], but the records in the request are [CNAME]. "
        "The record types of a service cannot be changed."
    )
    assert error.get("Message") == expected_message, f"unexpected InvalidInput message: {error.get('Message')!r}"

    unaffected = sd.get_service(Id=svc_id)["Service"]
    assert unaffected["DnsConfig"]["DnsRecords"][0]["Type"] == "A", "record type changed despite rejection"
    assert unaffected["DnsConfig"]["DnsRecords"][0]["TTL"] == 60, (
        f"expected TTL unchanged at 60, got {unaffected['DnsConfig']['DnsRecords'][0]['TTL']}"
    )

    # Positive control in the same file: a same-type TTL update on the same service succeeds.
    ok_resp = sd.update_service(
        Id=svc_id,
        Service={"DnsConfig": {"DnsRecords": [{"Type": "A", "TTL": 30}]}},
    )
    _wait_operation(sd, ok_resp["OperationId"])
    updated = sd.get_service(Id=svc_id)["Service"]
    assert updated["DnsConfig"]["DnsRecords"][0]["Type"] == "A", (
        f"expected record Type unchanged at A, got {updated['DnsConfig']['DnsRecords'][0]['Type']!r}"
    )
    assert updated["DnsConfig"]["DnsRecords"][0]["TTL"] == 30, "same-type TTL update did not persist"


def _client_error(fn):
    """Call fn(); return its botocore Error dict. An unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]
    raise AssertionError(f"expected a ClientError, but the call succeeded: {result!r}")


def _wait_operation(sd, operation_id, timeout_s: float = 180.0, interval_s: float = 3.0):
    deadline = time.monotonic() + timeout_s
    while True:
        op = sd.get_operation(OperationId=operation_id)["Operation"]
        status = op["Status"]
        if status == "SUCCESS":
            return op
        if status == "FAIL":
            raise AssertionError(
                f"operation {operation_id} failed: {op.get('ErrorCode')} {op.get('ErrorMessage')}"
            )
        if time.monotonic() >= deadline:
            raise AssertionError(f"operation {operation_id} stuck in {status} after {timeout_s}s")
        time.sleep(interval_s)


def _delete_namespace_best_effort(sd, namespace_id):
    from botocore.exceptions import ClientError

    try:
        op_id = sd.delete_namespace(Id=namespace_id)["OperationId"]
        _wait_operation(sd, op_id, timeout_s=180.0)
    except ClientError as e:
        if e.response["Error"]["Code"] != "NamespaceNotFound":
            raise


def _delete_service_best_effort(sd, service_id):
    from botocore.exceptions import ClientError

    try:
        sd.delete_service(Id=service_id)
    except ClientError as e:
        if e.response["Error"]["Code"] != "ServiceNotFound":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
