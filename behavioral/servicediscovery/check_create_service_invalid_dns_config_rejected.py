"""create-service-invalid-dns-config-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-service-invalid-dns-config-rejected"
GROUP = "negative-classes"
SERVICES = ["servicediscovery"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateService with a CNAME DnsConfig record paired with the MULTIVALUE
    routing policy (CNAME only supports WEIGHTED) is rejected with InvalidInput and
    no service is created, while the same CNAME record under WEIGHTED succeeds."""
    sd = ctx.client("servicediscovery")
    name = f"{ctx.unique_name('sim2real-pubns-')}.com"

    create_op_id = sd.create_public_dns_namespace(
        Name=name, Tags=[{"Key": "sim2real-check", "Value": CHECK}]
    )["OperationId"]
    op = _poll_operation(ctx, sd, create_op_id, timeout_s=180.0)
    assert op["Status"] == "SUCCESS", f"namespace create failed: {op.get('ErrorMessage')}"
    ns_id = op["Targets"]["NAMESPACE"]
    ctx.on_cleanup(lambda: _safe_delete_namespace(sd, ns_id))

    bad_svc_name = ctx.unique_name("sim2real-svc-bad-")
    code, message = _error(
        lambda: sd.create_service(
            Name=bad_svc_name,
            NamespaceId=ns_id,
            DnsConfig={
                "DnsRecords": [{"Type": "CNAME", "TTL": 60}],
                "RoutingPolicy": "MULTIVALUE",
            },
        )
    )
    assert code == "InvalidInput", f"expected InvalidInput for CNAME+MULTIVALUE, got {code!r}"
    assert message == "WEIGHTED routing policy must be used with DNS Record Type CNAME", f"unexpected InvalidInput message: {message!r}"

    # Effect absent: no service with that name exists under the namespace.
    matches = sd.list_services(
        Filters=[{"Name": "NAMESPACE_ID", "Values": [ns_id], "Condition": "EQ"}]
    )["Services"]
    assert bad_svc_name not in [s["Name"] for s in matches], (
        f"rejected create_service must not create a service, found {matches}"
    )

    # Positive control: same CNAME record, WEIGHTED routing policy, succeeds.
    good_svc_name = ctx.unique_name("sim2real-svc-good-")
    created = sd.create_service(
        Name=good_svc_name,
        NamespaceId=ns_id,
        DnsConfig={"DnsRecords": [{"Type": "CNAME", "TTL": 60}], "RoutingPolicy": "WEIGHTED"},
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )["Service"]
    svc_id = created["Id"]
    ctx.on_cleanup(lambda: _safe_delete_service(sd, svc_id))

    # Independent read at the destination, not the mutating call's own response.
    svc = sd.get_service(Id=svc_id)["Service"]
    assert svc["DnsConfig"]["RoutingPolicy"] == "WEIGHTED", (
        f"expected WEIGHTED routing policy to persist, got {svc['DnsConfig']['RoutingPolicy']!r}"
    )


def _error(fn):
    """Call fn() and return the (code, message) of the ClientError it raises. An unexpected
    success raises, so accepting what AWS refuses never reads as a code mismatch."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


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
