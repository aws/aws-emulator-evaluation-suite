"""list-application-dpu-sizes-server-managed-set."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "list-application-dpu-sizes-server-managed-set"
GROUP = "server-side"
SERVICES = ["athena"]


@tags("axis:happy-path", "cap:c5", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListApplicationDPUSizes returns the fixed, centrally-managed set of DPU sizes each
    application runtime supports (e.g. 'Athena notebook version 1'), not a value the
    caller configures, and the set is identical across repeated calls."""
    athena = ctx.client("athena")

    first = _collect_dpu_sizes(athena)
    assert len(first) > 0, "ListApplicationDPUSizes returned an empty catalog"

    by_runtime = {}
    for entry in first:
        runtime_id = entry["ApplicationRuntimeId"]
        sizes = entry["SupportedDPUSizes"]
        assert len(sizes) > 0, f"{runtime_id!r} advertises no supported DPU sizes"
        assert all(isinstance(size, int) and size > 0 for size in sizes), (
            f"{runtime_id!r} supported sizes are not all positive ints: {sizes!r}"
        )
        by_runtime[runtime_id] = tuple(sorted(sizes))

    assert any("notebook" in runtime_id.lower() for runtime_id in by_runtime), by_runtime

    second = {
        entry["ApplicationRuntimeId"]: tuple(sorted(entry["SupportedDPUSizes"]))
        for entry in _collect_dpu_sizes(athena)
    }
    assert second == by_runtime, (
        f"ListApplicationDPUSizes is not stable across calls: {by_runtime!r} != {second!r}"
    )


def _collect_dpu_sizes(athena) -> list[dict]:
    out: list[dict] = []
    kwargs: dict = {}
    while True:
        resp = athena.list_application_dpu_sizes(**kwargs)
        out.extend(resp["ApplicationDPUSizes"])
        token = resp.get("NextToken")
        if not token:
            break
        kwargs["NextToken"] = token
    return out


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
