"""put-get-parameter-roundtrip."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "put-get-parameter-roundtrip"
GROUP = 'state-machine'
SERVICES = ['ssm']

@tags("axis:happy-path", "cap:c1", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """PutParameter creates a String parameter retrievable via GetParameter with Version=1."""

    ssm = ctx.client("ssm")

    def _param_name(suffix=""):
        # SSM requires a leading '/' for any hierarchical (slash-containing) name.
        return "/" + ctx.unique_name("sim2real-behav-" + suffix)

    def _track_parameter(name):
        ctx.on_cleanup(lambda: ssm.delete_parameter(Name=name))
        return name

    name = _param_name("probe-param-")
    _track_parameter(name)

    put_resp = ssm.put_parameter(
        Name=name,
        Value="hello-world",
        Type="String",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    assert put_resp["Version"] == 1, f"expected initial version 1, got {put_resp['Version']}"

    got = ssm.get_parameter(Name=name)["Parameter"]
    assert got["Value"] == "hello-world", f"unexpected value: {got['Value']}"
    assert got["Type"] == "String", f"expected Type String, got {got['Type']}"
    assert got["Version"] == 1, f"expected Version 1, got {got['Version']}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
