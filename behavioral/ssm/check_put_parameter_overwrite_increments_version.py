"""put-parameter-overwrite-increments-version."""
from __future__ import annotations

from behavioral_harness import tags


CHECK = "put-parameter-overwrite-increments-version"
GROUP = 'state-machine'
SERVICES = ['ssm']

@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """Overwriting a parameter increments its Version by exactly 1 each time."""

    ssm = ctx.client("ssm")

    def _param_name(suffix=""):
        # SSM requires a leading '/' for any hierarchical (slash-containing) name.
        return "/" + ctx.unique_name("sim2real-behav-" + suffix)

    def _track_parameter(name):
        ctx.on_cleanup(lambda: ssm.delete_parameter(Name=name))
        return name

    name = _param_name("probe-param-overwrite-")
    _track_parameter(name)

    v1 = ssm.put_parameter(
        Name=name, Value="v1", Type="String", Tags=[{"Key": "sim2real", "Value": CHECK}]
    )["Version"]
    v2 = ssm.put_parameter(Name=name, Value="v2", Type="String", Overwrite=True)["Version"]
    v3 = ssm.put_parameter(Name=name, Value="v3", Type="String", Overwrite=True)["Version"]

    assert (v1, v2, v3) == (1, 2, 3), f"expected sequential versions, got {(v1, v2, v3)}"

    got = ssm.get_parameter(Name=name)["Parameter"]
    assert got["Value"] == "v3", f"expected independent read to see 'v3', got {got['Value']!r}"
    assert got["Version"] == 3, f"expected independent read Version == 3, got {got['Version']!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
