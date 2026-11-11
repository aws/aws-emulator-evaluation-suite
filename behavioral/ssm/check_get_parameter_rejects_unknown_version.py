"""get-parameter-rejects-unknown-version."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-parameter-rejects-unknown-version"
GROUP = 'overly-permissive'
SERVICES = ['ssm']

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetParameter fails ParameterNotFound for a missing name and ParameterVersionNotFound for a
    nonexistent version of an existing name, while an existing version selector resolves."""

    ssm = ctx.client("ssm")

    def _param_name(suffix=""):
        # SSM requires a leading '/' for any hierarchical (slash-containing) name.
        return "/" + ctx.unique_name("sim2real-behav-" + suffix)

    def _track_parameter(name):
        ctx.on_cleanup(lambda: ssm.delete_parameter(Name=name))
        return name

    def _error_code(fn):
        """Return the ClientError code raised by fn; raise if the call unexpectedly succeeds."""
        try:
            result = fn()
        except ClientError as exc:
            err = exc.response.get("Error", {})
            return err.get("Code"), err.get("Message")
        raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")

    name = _param_name("probe-param-version-")
    _track_parameter(name)
    ssm.put_parameter(Name=name, Value="v1", Type="String")

    valid = ssm.get_parameter(Name=f"{name}:1")["Parameter"]
    assert valid["Value"] == "v1", f"selector ':1' must resolve the value just written, got {valid!r}"
    assert valid["Version"] == 1, f"selector ':1' must resolve Version 1, got {valid!r}"

    missing_name = _param_name("probe-param-missing-")
    code_missing_name, message_missing_name = _error_code(lambda: ssm.get_parameter(Name=missing_name))
    assert code_missing_name == "ParameterNotFound", f"expected ParameterNotFound, got {code_missing_name!r}"
    assert message_missing_name == "", message_missing_name

    code_missing_version, message_missing_version = _error_code(lambda: ssm.get_parameter(Name=f"{name}:99"))
    assert code_missing_version == "ParameterVersionNotFound", (
        f"expected ParameterVersionNotFound, got {code_missing_version!r}"
    )
    # SSM names a one-level parameter without its leading '/'.
    assert message_missing_version == (
        f"Systems Manager could not find version 99 of {name.lstrip('/')}. Verify the version and try again."
    ), message_missing_version


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
