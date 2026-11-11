"""list-operations-filter-by-status."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "list-operations-filter-by-status"
GROUP = 'operations'
SERVICES = ['servicediscovery']

@tags("axis:happy-path", "cap:c2", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListOperations with a Status=SUCCESS filter must surface an operation just driven to SUCCESS, with matching Id/Status."""

    sd = ctx.client("servicediscovery")

    def _poll_until(probe, predicate, *, timeout_s=60, interval_s=1.0, description="condition"):
        deadline = time.monotonic() + timeout_s
        last = None
        while time.monotonic() < deadline:
            last = probe()
            if predicate(last):
                return last
            time.sleep(interval_s)
        raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")

    def _wait_for_operation(operation_id, timeout_s=60, interval_s=1.5):
        # Poll GetOperation until it reaches a terminal state (SUCCESS or FAIL).
        return _poll_until(
            lambda: sd.get_operation(OperationId=operation_id)["Operation"],
            lambda op: op.get("Status") in ("SUCCESS", "FAIL"),
            timeout_s=timeout_s, interval_s=interval_s,
        )

    def _delete_namespace(namespace_id, wait=True):
        resp = sd.delete_namespace(Id=namespace_id)
        if wait:
            return _wait_for_operation(resp["OperationId"])
        return resp

    def _list_success_ops():
        # ListOperations can transiently lag operation completion (eventual
        # consistency), so this is polled to a full pagination pass rather
        # than trusted on the first read.
        by_id = {}
        next_token = None
        for _ in range(50):
            kwargs = {"Filters": [{"Name": "STATUS", "Values": ["SUCCESS"], "Condition": "EQ"}]}
            if next_token:
                kwargs["NextToken"] = next_token
            resp = sd.list_operations(**kwargs)
            for op in resp["Operations"]:
                by_id[op["Id"]] = op
            next_token = resp.get("NextToken")
            if not next_token:
                break
        return by_id

    create_resp = sd.create_http_namespace(Name=ctx.unique_name("sim2real-behav-sd-ns-listop-"))
    create_op_id = create_resp["OperationId"]
    op = _wait_for_operation(create_op_id)
    if op["Status"] != "SUCCESS":
        raise RuntimeError(f"CreateHttpNamespace failed: {op}")
    namespace_id = op["Targets"]["NAMESPACE"]
    ctx.on_cleanup(lambda: _delete_namespace(namespace_id))

    # The create operation itself just completed with SUCCESS; find it via
    # ListOperations, filtered by Status=SUCCESS -- an empty/absent-match
    # result must fail this check, not pass it vacuously.
    by_id = _poll_until(
        _list_success_ops,
        lambda ids: create_op_id in ids,
        timeout_s=60, interval_s=2.0,
        description=f"ListOperations(Status=SUCCESS) surfacing operation {create_op_id}",
    )
    assert all(o["Status"] == "SUCCESS" for o in by_id.values()), "filter must only return SUCCESS operations"
    assert by_id[create_op_id]["Status"] == "SUCCESS", (
        f"expected {create_op_id} Status=SUCCESS in filtered ListOperations, got {by_id[create_op_id]}"
    )

    # Cross-check with an independent GetOperation read on the same op id.
    detail = sd.get_operation(OperationId=create_op_id)["Operation"]
    assert detail["Status"] == "SUCCESS", f"GetOperation cross-check expected SUCCESS, got {detail.get('Status')}"
    assert detail["Id"] == create_op_id, f"GetOperation Id mismatch: expected {create_op_id}, got {detail.get('Id')}"

    _delete_namespace(namespace_id)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
