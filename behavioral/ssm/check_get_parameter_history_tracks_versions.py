"""get-parameter-history-tracks-versions."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "get-parameter-history-tracks-versions"
GROUP = 'state-machine'
SERVICES = ['ssm']

@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """GetParameterHistory returns one entry per PutParameter call, one per version, each holding
    the value it was written with."""

    ssm = ctx.client("ssm")

    def _param_name(suffix=""):
        # SSM requires a leading '/' for any hierarchical (slash-containing) name.
        return "/" + ctx.unique_name("sim2real-behav-" + suffix)

    def _track_parameter(name):
        ctx.on_cleanup(lambda: ssm.delete_parameter(Name=name))
        return name

    name = _param_name("probe-param-history-")
    _track_parameter(name)

    ssm.put_parameter(Name=name, Value="v1", Type="String")
    ssm.put_parameter(Name=name, Value="v2", Type="String", Overwrite=True)
    ssm.put_parameter(Name=name, Value="v3", Type="String", Overwrite=True)

    history = ssm.get_parameter_history(Name=name)["Parameters"]
    versions = sorted(p["Version"] for p in history)

    assert versions == [1, 2, 3], f"expected versions [1, 2, 3], got {versions}"
    values_by_version = {p["Version"]: p["Value"] for p in history}
    assert values_by_version[1] == "v1", f"expected version 1 == 'v1', got {values_by_version[1]!r}"
    assert values_by_version[2] == "v2", f"expected version 2 == 'v2', got {values_by_version[2]!r}"
    assert values_by_version[3] == "v3", f"expected version 3 == 'v3', got {values_by_version[3]!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
