"""cache-parameter-numeric-value-precision-preserved."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "cache-parameter-numeric-value-precision-preserved"
GROUP = "server-side"
SERVICES = ["elasticache"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A numeric cache parameter written via ModifyCacheParameterGroup is returned
    byte-identical (as a string) on DescribeCacheParameters -- no float/int coercion,
    no scientific notation, no trailing ".0"."""
    ec = ctx.client("elasticache")
    name = ctx.unique_name("sim2real-behav-pg-")
    ec.create_cache_parameter_group(
        CacheParameterGroupName=name,
        CacheParameterGroupFamily="redis7",
        Description="sim2real numeric parameter precision check",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: ec.delete_cache_parameter_group(CacheParameterGroupName=name))

    # A small integer parameter (range-bounded) and a larger byte-count integer
    # parameter -- both must round-trip as the exact string we sent.
    ec.modify_cache_parameter_group(
        CacheParameterGroupName=name,
        ParameterNameValues=[
            {"ParameterName": "maxmemory-samples", "ParameterValue": "7"},
            {"ParameterName": "repl-backlog-size", "ParameterValue": "2097152"},
        ],
    )

    params = {}
    marker = None
    while True:
        kwargs = {"CacheParameterGroupName": name}
        if marker:
            kwargs["Marker"] = marker
        resp = ec.describe_cache_parameters(**kwargs)
        for p in resp.get("Parameters", []):
            if "ParameterValue" not in p:
                continue
            params[p["ParameterName"]] = p["ParameterValue"]
        marker = resp.get("Marker")
        if not marker:
            break

    assert "maxmemory-samples" in params, "maxmemory-samples parameter missing from describe"
    assert params["maxmemory-samples"] == "7", (
        f"expected exact string '7', got {params['maxmemory-samples']!r} "
        "(float/int coercion would produce '7.0' or similar)"
    )
    assert "repl-backlog-size" in params, "repl-backlog-size parameter missing from describe"
    assert params["repl-backlog-size"] == "2097152", (
        f"expected exact string '2097152', got {params['repl-backlog-size']!r} "
        "(precision loss or scientific notation would corrupt this byte count)"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
