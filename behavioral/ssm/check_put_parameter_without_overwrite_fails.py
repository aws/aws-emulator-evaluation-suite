"""put-parameter-without-overwrite-fails."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-parameter-without-overwrite-fails"
GROUP = 'overly-permissive'
SERVICES = ['ssm']

@tags("axis:rejection", "cap:c1", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """Overly-permissive check: PutParameter on an existing name without Overwrite must fail."""

    ssm = ctx.client("ssm")

    def _client_error(fn):
        """Call fn(); return its (code, message). An unexpected SUCCESS raises."""
        try:
            result = fn()
        except ClientError as exc:
            err = exc.response.get("Error", {})
            return err.get("Code"), err.get("Message")
        raise AssertionError(f"expected ParameterAlreadyExists, but the call SUCCEEDED and returned {result!r}")

    def _param_name(suffix=""):
        # SSM requires a leading '/' for any hierarchical (slash-containing) name.
        return "/" + ctx.unique_name("sim2real-behav-" + suffix)

    def _track_parameter(name):
        ctx.on_cleanup(lambda: ssm.delete_parameter(Name=name))
        return name

    name = _param_name("probe-param-noverwrite-")
    _track_parameter(name)

    ssm.put_parameter(Name=name, Value="first", Type="String")

    code, message = _client_error(lambda: ssm.put_parameter(Name=name, Value="second", Type="String"))
    assert code == "ParameterAlreadyExists", f"expected ParameterAlreadyExists, got {code!r}"
    assert message == (
        "The parameter already exists. To overwrite this value, set the overwrite option in "
        "the request to true."
    ), f"unexpected message {message!r}"

    # The original value must be untouched.
    got = ssm.get_parameter(Name=name)["Parameter"]
    assert got["Value"] == "first", "value should not change after a rejected overwrite"

    # Restore: remove the blocking state, then the identical call (same Name/Value/Type,
    # still no Overwrite) must now succeed — proving the rejection was the pre-existing
    # name, not a blanket refusal of PutParameter.
    ssm.delete_parameter(Name=name)
    restored = ssm.put_parameter(Name=name, Value="second", Type="String")
    assert restored["Version"] == 1, f"expected fresh Version 1 after restore, got {restored['Version']!r}"

    got_after_restore = ssm.get_parameter(Name=name)["Parameter"]
    assert got_after_restore["Value"] == "second", "identical call should have taken effect after restore"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
