"""get-parameters-by-path-hierarchy."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "get-parameters-by-path-hierarchy"
GROUP = 'state-machine'
SERVICES = ['ssm']

@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """GetParametersByPath resolves Path by hierarchy segment, not string prefix.

    A recursive read returns exactly the two children with their values and excludes a sibling
    whose name only shares the path as a string prefix."""

    ssm = ctx.client("ssm")

    def _param_name(suffix=""):
        # SSM requires a leading '/' for any hierarchical (slash-containing) name.
        return "/" + ctx.unique_name("sim2real-behav-" + suffix)

    def _track_parameter(name):
        ctx.on_cleanup(lambda: ssm.delete_parameter(Name=name))
        return name

    base = _param_name("probe-hier-")
    child_a = f"{base}/a"
    child_b = f"{base}/b"
    # Shares `base` as a string prefix but is NOT a hierarchy descendant of it —
    # the boundary a naive startswith(path) implementation gets wrong.
    decoy_sibling = f"{base}x/c"
    _track_parameter(child_a)
    _track_parameter(child_b)
    _track_parameter(decoy_sibling)

    ssm.put_parameter(Name=child_a, Value="a", Type="String")
    ssm.put_parameter(Name=child_b, Value="b", Type="String")
    ssm.put_parameter(Name=decoy_sibling, Value="decoy", Type="String")

    resp = ssm.get_parameters_by_path(Path=base, Recursive=True)
    params = {p["Name"]: p["Value"] for p in resp["Parameters"]}

    assert set(params) == {child_a, child_b}, (
        f"expected exactly {{{child_a}, {child_b}}} under {base}, got {sorted(params)} "
        f"(a leaked {decoy_sibling!r} means Path was resolved as a string prefix, not a "
        "hierarchy segment)"
    )
    assert params == {child_a: "a", child_b: "b"}, (
        f"expected values preserved for both children, got {params}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
