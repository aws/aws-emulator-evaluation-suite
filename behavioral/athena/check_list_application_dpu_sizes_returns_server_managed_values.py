"""list-application-dpu-sizes-returns-server-managed-values."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "list-application-dpu-sizes-returns-server-managed-values"
GROUP = "server-side"
SERVICES = ["athena"]


@tags("axis:happy-path", "cap:c5", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListApplicationDPUSizes returns the fixed, server-managed catalog of supported DPU
    size configurations for notebook applications, identical across repeated calls."""
    athena = ctx.client("athena")

    sizes_1 = _collect_dpu_sizes(athena)
    assert len(sizes_1) >= 1, f"expected at least one ApplicationDPUSizes entry, got {sizes_1!r}"
    by_runtime_1 = {s["ApplicationRuntimeId"]: tuple(sorted(s["SupportedDPUSizes"])) for s in sizes_1}
    assert any("notebook" in rid.lower() for rid in by_runtime_1), (
        f"expected a notebook runtime among {sorted(by_runtime_1)}"
    )
    for rid, supported in by_runtime_1.items():
        assert 1 in supported, f"runtime {rid!r} supported DPU sizes {supported!r} missing 1"
        assert all(isinstance(n, int) and n >= 1 for n in supported), (
            f"runtime {rid!r} supported DPU sizes {supported!r} contain a non-positive-int entry"
        )

    sizes_2 = _collect_dpu_sizes(athena)
    by_runtime_2 = {s["ApplicationRuntimeId"]: tuple(sorted(s["SupportedDPUSizes"])) for s in sizes_2}
    assert by_runtime_2 == by_runtime_1, (
        f"ListApplicationDPUSizes is not stable across calls: {by_runtime_2!r} != {by_runtime_1!r}"
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
