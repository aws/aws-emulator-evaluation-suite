"""concurrent-create-service-same-name-conflict."""
from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "concurrent-create-service-same-name-conflict"
GROUP = "concurrency"
SERVICES = ["servicediscovery"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Firing several concurrent CreateService calls for the same Name under one
    namespace resolves to exactly one success and the rest ServiceAlreadyExists,
    never two live services with the same name."""
    sd = ctx.client("servicediscovery")
    name = f"{ctx.unique_name('sim2real-pubns-')}.com"

    create_op_id = sd.create_public_dns_namespace(Name=name)["OperationId"]
    op = _poll_operation(ctx, sd, create_op_id, timeout_s=180.0)
    assert op["Status"] == "SUCCESS", f"namespace create failed: {op.get('ErrorMessage')}"
    ns_id = op["Targets"]["NAMESPACE"]
    ctx.on_cleanup(lambda: _safe_delete_namespace(sd, ns_id))

    svc_name = ctx.unique_name("sim2real-svc-race-")
    dns_config = {"DnsRecords": [{"Type": "A", "TTL": 60}], "RoutingPolicy": "WEIGHTED"}

    def _racer(_i):
        try:
            resp = sd.create_service(Name=svc_name, NamespaceId=ns_id, DnsConfig=dns_config)
            return ("ok", resp["Service"]["Id"])
        except ClientError as e:
            return ("err", e.response["Error"]["Code"], e.response["Error"].get("Message"))

    with ThreadPoolExecutor(max_workers=6) as pool:
        results = list(pool.map(_racer, range(6)))

    oks = [r for r in results if r[0] == "ok"]
    errs = [r for r in results if r[0] == "err"]
    assert len(oks) == 1, f"expected exactly one winner, got {len(oks)}: {results}"
    assert len(errs) == 5, f"expected five losers, got {len(errs)}: {results}"
    assert all(code == "ServiceAlreadyExists" for _, code, _ in errs), (
        f"expected all losers to fail with ServiceAlreadyExists, got codes {[c for _, c, _ in errs]}"
    )
    assert all(message == "Service already exists." for _, _, message in errs), (
        f"expected every loser's message to be 'Service already exists.', got {[m for _, _, m in errs]}"
    )

    winner_id = oks[0][1]
    ctx.on_cleanup(lambda: _safe_delete_service(sd, winner_id))

    matches = sd.list_services(
        Filters=[{"Name": "NAMESPACE_ID", "Values": [ns_id], "Condition": "EQ"}]
    )["Services"]
    same_name = [s for s in matches if s["Name"] == svc_name]
    assert len(same_name) == 1, f"expected exactly one live service named {svc_name!r}, got {same_name}"
    assert same_name[0]["Id"] == winner_id, (
        f"expected the listed service to be the concurrency winner {winner_id!r}, "
        f"got {same_name[0]['Id']!r}"
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
