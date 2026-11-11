"""get-parameter-invalid-label-fails."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-parameter-invalid-label-fails"
GROUP = 'overly-permissive'
SERVICES = ['ssm']

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """GetParameter by a never-assigned label on an existing parameter fails with
    ParameterVersionNotFound, not ParameterNotFound; an attached label resolves first."""

    ssm = ctx.client("ssm")

    def _error_code(fn):
        try:
            result = fn()
        except ClientError as exc:
            err = exc.response.get("Error", {})
            return err.get("Code"), err.get("Message")
        raise AssertionError(
            f"expected a ClientError, but the call SUCCEEDED and returned {result!r}"
        )

    def _param_name(suffix=""):
        # SSM requires a leading '/' for any hierarchical (slash-containing) name.
        return "/" + ctx.unique_name("sim2real-behav-" + suffix)

    def _track_parameter(name):
        ctx.on_cleanup(lambda: ssm.delete_parameter(Name=name))
        return name

    name = _param_name("probe-param-badlabel-")
    _track_parameter(name)

    ssm.put_parameter(Name=name, Value="v1", Type="String")

    attach = ssm.label_parameter_version(
        Name=name, ParameterVersion=1, Labels=["sim2real-attached"]
    )
    assert attach.get("InvalidLabels", []) == [], (
        f"a conforming label must not come back under InvalidLabels: {attach}"
    )

    attached = ssm.get_parameter(Name=f"{name}:sim2real-attached")["Parameter"]
    assert attached["Version"] == 1, (
        f"an attached label must resolve Version 1, got {attached}"
    )
    assert attached["Value"] == "v1", (
        f"an attached label must resolve the correct value, got {attached['Value']!r}"
    )

    code, message = _error_code(lambda: ssm.get_parameter(Name=f"{name}:no-such-label"))
    assert code == "ParameterVersionNotFound", (
        f"expected ParameterVersionNotFound, got {code!r}"
    )
    # SSM names a one-level parameter without its leading '/'.
    assert message == (
        f"Systems Manager could not find a version of {name.lstrip('/')} that has the specified "
        "label, no-such-label. Verify the parameter label and try again."
    ), message


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
