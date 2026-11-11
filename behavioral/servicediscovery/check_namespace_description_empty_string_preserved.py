"""namespace-description-empty-string-preserved."""
from __future__ import annotations

import time
from typing import Any

from behavioral_harness import tags

CHECK = "namespace-description-empty-string-preserved"
GROUP = "representation"
SERVICES = ["servicediscovery"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateHttpNamespace with Description "" reads back with no Description, exactly like an omitted
    one, while a non-empty Description round-trips through GetNamespace."""
    with_empty_name = ctx.unique_name("sim2real-behav-ns-empty-")
    without_name = ctx.unique_name("sim2real-behav-ns-omit-")
    with_value_name = ctx.unique_name("sim2real-behav-ns-value-")
    control_description = "sim2real-control-description"

    ns_with_empty = _create_http_namespace(ctx, with_empty_name, Description="")
    ns_without = _create_http_namespace(ctx, without_name)
    ns_with_value = _create_http_namespace(ctx, with_value_name, Description=control_description)

    sd = ctx.client("servicediscovery")
    resp_with_empty = sd.get_namespace(Id=ns_with_empty)["Namespace"]
    resp_without = sd.get_namespace(Id=ns_without)["Namespace"]
    resp_with_value = sd.get_namespace(Id=ns_with_value)["Namespace"]

    # Positive control: a non-empty Description must round-trip, proving the field
    # is genuinely populated by this account/region and ruling out a target that
    # simply never implements Description regardless of input.
    assert resp_with_value.get("Description") == control_description, (
        f"a non-empty Description must be preserved by GetNamespace (positive control), "
        f"got {resp_with_value.get('Description')!r}"
    )

    # An explicit empty-string Description is normalized away by
    # the service -- GetNamespace omits the field entirely, exactly as it does when
    # Description was never supplied at all. The two create paths are indistinguishable.
    assert "Description" not in resp_with_empty, (
        f"expected empty-string Description to be normalized away, got "
        f"{resp_with_empty.get('Description')!r}"
    )
    assert "Description" not in resp_without, (
        f"a namespace created with no Description at all should omit the field, got "
        f"{resp_without.get('Description')!r}"
    )
    assert resp_with_empty.get("Description") == resp_without.get("Description"), (
        "explicit empty-string Description should be indistinguishable from an omitted one"
    )


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


def _create_http_namespace(ctx, name: str, **kwargs) -> str:
    sd = ctx.client("servicediscovery")
    op_id = sd.create_http_namespace(Name=name, **kwargs)["OperationId"]
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


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
