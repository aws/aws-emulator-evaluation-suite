"""get-nonexistent-parameter-fails."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-nonexistent-parameter-fails"
GROUP = 'overly-permissive'
SERVICES = ['ssm']

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetParameter on an unknown name fails ParameterNotFound, while an existing name resolves.

    DescribeParameters also lists nothing for the name, and it resolves once created."""

    ssm = ctx.client("ssm")

    def _error_code(fn):
        try:
            result = fn()
        except ClientError as exc:
            err = exc.response.get("Error", {})
            return err.get("Code"), err.get("Message")
        raise AssertionError(f"expected a ClientError, call unexpectedly succeeded: {result!r}")

    def _param_name(suffix=""):
        # SSM requires a leading '/' for any hierarchical (slash-containing) name.
        return "/" + ctx.unique_name("sim2real-behav-" + suffix)

    control_name = _param_name("probe-param-control-")
    name = _param_name("probe-param-missing-")

    ssm.put_parameter(Name=control_name, Value="control-value", Type="String")
    ctx.on_cleanup(lambda: ssm.delete_parameter(Name=control_name))
    control = ssm.get_parameter(Name=control_name)
    assert control["Parameter"]["Value"] == "control-value", (
        f"positive control failed: expected 'control-value', got "
        f"{control['Parameter']['Value']!r}"
    )

    code, message = _error_code(lambda: ssm.get_parameter(Name=name))
    assert code == "ParameterNotFound", f"expected ParameterNotFound, got {code!r}"
    assert message == "", message

    described = ssm.describe_parameters(ParameterFilters=[{"Key": "Name", "Values": [name]}])
    assert described["Parameters"] == [], (
        f"expected no parameter named {name!r} in DescribeParameters, got "
        f"{described['Parameters']!r}"
    )

    ssm.put_parameter(Name=name, Value="now-exists", Type="String")
    ctx.on_cleanup(lambda: ssm.delete_parameter(Name=name))
    restored = ssm.get_parameter(Name=name)
    assert restored["Parameter"]["Value"] == "now-exists", (
        f"expected {name!r} to resolve after creation, got "
        f"{restored['Parameter']['Value']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
