"""cache-parameter-numeric-precision-round-trip."""
from __future__ import annotations

import re

from behavioral_harness import tags

CHECK = "cache-parameter-numeric-precision-round-trip"
GROUP = "representation"
SERVICES = ["elasticache"]

_RANGE_RE = re.compile(r"^(\d+)-(\d+)$")


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A numeric cache parameter written via ModifyCacheParameterGroup is returned unchanged,
    with no rounding or precision loss, by DescribeCacheParameters."""
    ec = ctx.client("elasticache")
    name = ctx.unique_name("sim2real-numcpg-")
    ec.create_cache_parameter_group(
        CacheParameterGroupName=name,
        CacheParameterGroupFamily="redis7",
        Description="numeric precision round-trip test group",
    )
    ctx.on_cleanup(lambda: ec.delete_cache_parameter_group(CacheParameterGroupName=name))

    params = ec.describe_cache_parameters(CacheParameterGroupName=name)["Parameters"]
    best = None
    best_span = -1
    for p in params:
        if not p.get("IsModifiable") or p.get("DataType") != "integer":
            continue
        m = _RANGE_RE.match(p.get("AllowedValues") or "")
        if not m:
            continue
        lo, hi = int(m.group(1)), int(m.group(2))
        span = hi - lo
        if span > best_span:
            best_span = span
            best = (p["ParameterName"], lo, hi)

    if best is None or best_span < 1000:
        raise AssertionError(
            "no modifiable integer parameter with a wide numeric range was found in the "
            "redis7 CacheParameterGroupDetails; cannot exercise a numeric precision round-trip "
            "(would need a live redis7-family cache parameter group listing to pick a target)"
        )

    param_name, lo, _hi = best
    target_value = lo + min(best_span - 1, 123456789)
    ec.modify_cache_parameter_group(
        CacheParameterGroupName=name,
        ParameterNameValues=[{"ParameterName": param_name, "ParameterValue": str(target_value)}],
    )

    refreshed = ec.describe_cache_parameters(CacheParameterGroupName=name)["Parameters"]
    by_name = {p["ParameterName"]: p.get("ParameterValue") for p in refreshed}
    assert param_name in by_name, f"parameter {param_name} missing from DescribeCacheParameters after modify"
    assert by_name[param_name] == str(target_value), (
        f"parameter {param_name} round-tripped as {by_name[param_name]!r}, expected {target_value!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
