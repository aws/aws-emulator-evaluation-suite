"""delete-parameter-then-get-fails."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-parameter-then-get-fails"
GROUP = 'state-machine'
SERVICES = ['ssm']

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """State machine: after DeleteParameter, the parameter no longer exists for GetParameter,
    a mutation on the same id is also rejected, and the freed name is reusable."""

    ssm = ctx.client("ssm")

    def _error_code(fn):
        try:
            fn()
        except ClientError as exc:
            err = exc.response.get("Error", {})
            return err.get("Code"), err.get("Message")
        raise AssertionError("expected a ClientError but the call succeeded")

    def _param_name(suffix=""):
        # SSM requires a leading '/' for any hierarchical (slash-containing) name.
        return "/" + ctx.unique_name("sim2real-behav-" + suffix)

    def _cleanup():
        try:
            ssm.delete_parameter(Name=name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ParameterNotFound":
                raise

    name = _param_name("probe-param-delete-")
    ssm.put_parameter(Name=name, Value="temp", Type="String")
    ctx.on_cleanup(_cleanup)

    ssm.delete_parameter(Name=name)

    code, message = _error_code(lambda: ssm.get_parameter(Name=name))
    assert code == "ParameterNotFound", f"expected ParameterNotFound after delete, got {code!r}"
    assert message == "", message

    redelete_code, redelete_message = _error_code(lambda: ssm.delete_parameter(Name=name))
    assert redelete_code == "ParameterNotFound", (
        f"expected ParameterNotFound re-deleting an already-deleted parameter, got {redelete_code!r}"
    )
    assert redelete_message == "", redelete_message

    ssm.put_parameter(Name=name, Value="reused", Type="String")
    reused = ssm.get_parameter(Name=name)["Parameter"]["Value"]
    assert reused == "reused", f"expected the freed name to be reusable, got {reused!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
