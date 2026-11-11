"""delete-nonexistent-parameter-fails."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-nonexistent-parameter-fails"
GROUP = 'overly-permissive'
SERVICES = ['ssm']

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteParameter on a never-created name must fail rather than succeed silently.
    A positive control deletes a just-created parameter, so the failure is not blanket."""

    ssm = ctx.client("ssm")

    def _rejects(fn):
        """Call fn() and return its (error code, message); an unexpected success raises."""
        try:
            result = fn()
        except ClientError as exc:
            err = exc.response.get("Error", {})
            return err.get("Code"), err.get("Message")
        raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")

    def _param_name(suffix=""):
        # SSM requires a leading '/' for any hierarchical (slash-containing) name.
        return "/" + ctx.unique_name("sim2real-behav-" + suffix)

    real_name = _param_name("probe-param-delete-missing-real-")

    def _cleanup_real():
        try:
            ssm.delete_parameter(Name=real_name)
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "ParameterNotFound":
                raise

    ctx.on_cleanup(_cleanup_real)

    # Positive control: DeleteParameter must work at all, on a parameter this check just created.
    ssm.put_parameter(Name=real_name, Value="value", Type="String")
    got = ssm.get_parameter(Name=real_name)["Parameter"]
    assert got["Value"] == "value", f"expected the just-created value, got {got!r}"

    ssm.delete_parameter(Name=real_name)

    # Independent read proves the delete actually took.
    code, message = _rejects(lambda: ssm.get_parameter(Name=real_name))
    assert code == "ParameterNotFound", f"expected ParameterNotFound after delete, got {code!r}"
    assert message == "", message

    # A mutation on the now-dead id also fails, not just a read.
    code, message = _rejects(lambda: ssm.delete_parameter(Name=real_name))
    assert code == "ParameterNotFound", f"expected ParameterNotFound on double-delete, got {code!r}"
    assert message == "", message

    # The subject under test: DeleteParameter on a name that was NEVER created must fail too.
    never_created_name = _param_name("probe-param-delete-missing-never-created-")
    code, message = _rejects(lambda: ssm.delete_parameter(Name=never_created_name))
    assert code == "ParameterNotFound", f"expected ParameterNotFound, got {code!r}"
    assert message == "", message


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
