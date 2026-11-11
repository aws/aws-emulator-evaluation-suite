"""create-graph-kms-encryption-reflects-key."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-graph-kms-encryption-reflects-key"
GROUP = "cross-service"
SERVICES = ["neptune-graph"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A graph created with a customer-managed KMS key reaches AVAILABLE and GetGraph reports that exact
    key ARN as kmsKeyIdentifier."""
    kms = ctx.client("kms")
    ng = ctx.client("neptune-graph")

    key = kms.create_key(
        Description=ctx.unique_name("sim2real-ng-key-"),
        Tags=[{"TagKey": "sim2real-owner", "TagValue": "behavioral-check"}],
    )["KeyMetadata"]
    key_arn = key["Arn"]
    key_id = key["KeyId"]

    def _cleanup_key() -> None:
        try:
            kms.schedule_key_deletion(KeyId=key_id, PendingWindowInDays=7)
        except ClientError as e:
            if e.response["Error"]["Code"] != "NotFoundException":
                raise

    ctx.on_cleanup(_cleanup_key)

    name = ctx.unique_name("sim2real-ng-")
    resp = ng.create_graph(
        graphName=name,
        provisionedMemory=16,
        publicConnectivity=False,
        kmsKeyIdentifier=key_arn,
        tags={"sim2real-owner": "behavioral-check"},
    )
    graph_id = resp["id"]

    def _cleanup_graph() -> None:
        def _settle(timeout_s):
            return _poll_until(
                lambda: ng.get_graph(graphIdentifier=graph_id),
                lambda g: g["status"] not in ("CREATING", "UPDATING"),
                timeout_s=timeout_s,
                interval_s=2,
            )

        try:
            if _settle(1200).get("deletionProtection"):
                ng.update_graph(graphIdentifier=graph_id, deletionProtection=False)
                _settle(120)
            ng.delete_graph(graphIdentifier=graph_id, skipSnapshot=True)
        except ClientError as e:
            if e.response["Error"]["Code"] != "ResourceNotFoundException":
                raise

    ctx.on_cleanup(_cleanup_graph)
    status = _poll_until(
        lambda: ng.get_graph(graphIdentifier=graph_id)["status"],
        lambda s: s in ("AVAILABLE", "FAILED"),
        timeout_s=1500,
        interval_s=15,
    )
    assert status == "AVAILABLE", f"expected graph {graph_id} to reach AVAILABLE, got {status!r}"

    final = ng.get_graph(graphIdentifier=graph_id)
    assert final["kmsKeyIdentifier"] == key_arn, (
        f"expected GetGraph to reflect kmsKeyIdentifier {key_arn!r}, got {final.get('kmsKeyIdentifier')!r}"
    )


# ===== helpers =====
def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while True:
        last = probe()
        if predicate(last):
            return last
        if time.monotonic() >= deadline:
            raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")
        time.sleep(interval_s)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
