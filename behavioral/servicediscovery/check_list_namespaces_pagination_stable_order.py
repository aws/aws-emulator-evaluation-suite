"""list-namespaces-pagination-stable-order."""
from __future__ import annotations

import time
from typing import Any

from behavioral_harness import tags

CHECK = "list-namespaces-pagination-stable-order"
GROUP = "ordering"
SERVICES = ["servicediscovery"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListNamespaces filtered to this run's name prefix and paginated with a small fixed page
    size returns exactly the created namespaces, each once, and preserves the same relative order
    across two independent full pagination passes."""
    sd = ctx.client("servicediscovery")
    prefix = ctx.unique_name("sim2real-behav-nspg-")
    created_ids: list[str] = []
    for i in range(5):
        created_ids.append(_create_http_namespace(ctx, f"{prefix}-{i}"))

    pass_a = _paginate_all_namespace_ids(sd, page_size=2, prefix=prefix)
    pass_b = _paginate_all_namespace_ids(sd, page_size=2, prefix=prefix)

    # No duplicates and no gaps within a single pass.
    assert len(pass_a) == len(set(pass_a)), "duplicate namespace id within one ListNamespaces pagination pass"
    created_set = set(created_ids)
    assert set(pass_a) == created_set, (
        f"the prefix-filtered pagination did not return exactly the created namespaces: missing "
        f"{created_set - set(pass_a)}, extra {set(pass_a) - created_set}"
    )

    # The relative order of *our* namespaces must be identical across both passes.
    order_a = [nid for nid in pass_a if nid in created_set]
    order_b = [nid for nid in pass_b if nid in created_set]
    assert order_a == order_b, f"pagination order not stable across passes: {order_a} != {order_b}"
    assert len(order_a) == len(created_ids), "some created namespaces missing from the ordered subset"


def _wait_operation(ctx, operation_id: str, timeout_s: float = 240.0, interval_s: float = 3.0) -> dict[str, Any]:
    sd = ctx.client("servicediscovery")
    deadline = time.monotonic() + timeout_s
    op: dict[str, Any] | None = None
    while time.monotonic() < deadline:
        op = sd.get_operation(OperationId=operation_id)["Operation"]
        if op["Status"] in ("SUCCESS", "FAIL"):
            return op
        time.sleep(interval_s)
    raise AssertionError(f"operation {operation_id} did not reach a terminal state within {timeout_s}s (last={op})")


def _create_http_namespace(ctx, name: str) -> str:
    sd = ctx.client("servicediscovery")
    op_id = sd.create_http_namespace(Name=name, Tags=[{"Key": "sim2real-check", "Value": CHECK}])["OperationId"]
    op = _wait_operation(ctx, op_id)
    assert op["Status"] == "SUCCESS", f"namespace create failed: {op}"
    namespace_id = op["Targets"]["NAMESPACE"]

    def _cleanup():
        try:
            del_op_id = sd.delete_namespace(Id=namespace_id)["OperationId"]
            _wait_operation(ctx, del_op_id)
        except sd.exceptions.NamespaceNotFound:
            pass

    ctx.on_cleanup(_cleanup)
    return namespace_id


def _paginate_all_namespace_ids(sd, page_size: int, prefix: str) -> list[str]:
    ids: list[str] = []
    next_token = None
    while True:
        kwargs = {
            "MaxResults": page_size,
            "Filters": [{"Name": "NAME", "Values": [prefix], "Condition": "BEGINS_WITH"}],
        }
        if next_token:
            kwargs["NextToken"] = next_token
        resp = sd.list_namespaces(**kwargs)
        ids.extend(ns["Id"] for ns in resp.get("Namespaces", []))
        next_token = resp.get("NextToken")
        if not next_token:
            break
    return ids


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
