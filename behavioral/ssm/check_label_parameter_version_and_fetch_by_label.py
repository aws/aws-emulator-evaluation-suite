"""label-parameter-version-and-fetch-by-label."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "label-parameter-version-and-fetch-by-label"
GROUP = 'state-machine'
SERVICES = ['ssm']

@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """LabelParameterVersion attaches a label that GetParameter can resolve via Name:label."""

    ssm = ctx.client("ssm")

    def _param_name(suffix=""):
        # SSM requires a leading '/' for any hierarchical (slash-containing) name.
        return "/" + ctx.unique_name("sim2real-behav-" + suffix)

    def _track_parameter(name):
        ctx.on_cleanup(lambda: ssm.delete_parameter(Name=name))
        return name

    name = _param_name("probe-param-label-")
    _track_parameter(name)

    ssm.put_parameter(Name=name, Value="v1", Type="String")
    ssm.put_parameter(Name=name, Value="v2", Type="String", Overwrite=True)

    ssm.label_parameter_version(Name=name, ParameterVersion=1, Labels=["stable"])

    labeled = ssm.get_parameter(Name=f"{name}:stable")["Parameter"]
    assert labeled["Value"] == "v1", f"expected labeled version to resolve to v1, got {labeled['Value']}"
    assert labeled["Version"] == 1, f"expected the ':stable' selector to resolve Version 1, got {labeled['Version']}"

    latest = ssm.get_parameter(Name=name)["Parameter"]
    assert latest["Value"] == "v2", "unlabeled fetch must still return the latest version"
    assert latest["Version"] == 2, (
        f"labeling version 1 must not perturb the unlabeled fetch's version, got {latest['Version']}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
