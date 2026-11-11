"""put-parameter-rejects-pattern-mismatch."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-parameter-rejects-pattern-mismatch"
GROUP = 'overly-permissive'
SERVICES = ['ssm']

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """PutParameter rejects a Value violating AllowedPattern with ParameterPatternMismatchException
    and creates nothing, while a matching Value is accepted and readable."""

    ssm = ctx.client("ssm")

    def _param_name(suffix=""):
        # SSM requires a leading '/' for any hierarchical (slash-containing) name.
        return "/" + ctx.unique_name("sim2real-behav-" + suffix)

    def _delete_parameter(name):
        # Teardown: the rejected write never created its parameter, which answers ParameterNotFound.
        try:
            ssm.delete_parameter(Name=name)
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "ParameterNotFound":
                raise

    def _track_parameter(name):
        ctx.on_cleanup(lambda: _delete_parameter(name))
        return name

    def _error_code(fn):
        """Return the ClientError (code, message) raised by fn; raise if the call unexpectedly succeeds."""
        try:
            result = fn()
        except ClientError as exc:
            err = exc.response.get("Error", {})
            return err.get("Code"), err.get("Message")
        raise AssertionError(
            f"expected a ClientError, but the call SUCCEEDED and returned {result!r}"
        )

    pattern = "^[0-9]+$"

    control_name = _param_name("probe-param-pattern-control-")
    _track_parameter(control_name)
    control = ssm.put_parameter(
        Name=control_name, Value="12345", Type="String", AllowedPattern=pattern
    )
    assert control["Version"] == 1, (
        f"a first write whose Value satisfies AllowedPattern must be accepted, got {control!r}"
    )
    assert ssm.get_parameter(Name=control_name)["Parameter"]["Value"] == "12345", (
        "the accepted control write must be readable back with the value that was stored"
    )

    name = _param_name("probe-param-pattern-")
    _track_parameter(name)

    code, message = _error_code(
        lambda: ssm.put_parameter(
            Name=name,
            Value="not-numeric",
            Type="String",
            AllowedPattern=pattern,
        )
    )
    assert code == "ParameterPatternMismatchException", (
        f"expected ParameterPatternMismatchException, got {code!r}"
    )
    assert message == f"Parameter value, cannot be validated against allowedPattern: {pattern}", message

    assert _error_code(lambda: ssm.get_parameter(Name=name)) == ("ParameterNotFound", ""), (
        "a rejected PutParameter must not create the parameter"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
