"""delete-parameters-batch-partial-failure."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-parameters-batch-partial-failure"
GROUP = 'state-machine'
SERVICES = ['ssm']

@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeleteParameters deletes existing names and reports unknown ones separately.

    An unknown name in the batch must be echoed under InvalidParameters, never
    turned into a top-level error that fails the whole batch.
    """

    ssm = ctx.client("ssm")

    def _param_name(suffix=""):
        # These are flat (non-hierarchical) names: SSM normalizes away a leading
        # '/' on a name with no internal slash and echoes it back without one, so
        # DeletedParameters/InvalidParameters would not match a slash-prefixed
        # name. Use the bare name to keep created and echoed names identical.
        return ctx.unique_name("sim2real-behav-" + suffix)

    def _track_parameter(name):
        ctx.on_cleanup(lambda: _delete_parameter_if_present(ssm, name))
        return name

    def _error(fn):
        try:
            result = fn()
        except ClientError as exc:
            return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
        raise AssertionError(f"expected a ClientError, call unexpectedly succeeded: {result!r}")

    name1 = _param_name("probe-param-batchdel-")
    name2 = _param_name("probe-param-batchdel-")
    missing = _param_name("probe-param-batchdel-missing-")
    _track_parameter(name1)
    _track_parameter(name2)
    ssm.put_parameter(Name=name1, Value="a", Type="String")
    ssm.put_parameter(Name=name2, Value="b", Type="String")

    resp = ssm.delete_parameters(Names=[name1, name2, missing])
    assert sorted(resp["DeletedParameters"]) == sorted([name1, name2]), resp
    assert resp["InvalidParameters"] == [missing], resp

    # AWS answers ParameterNotFound with an empty message.
    code1, message1 = _error(lambda: ssm.get_parameter(Name=name1))
    assert code1 == "ParameterNotFound", f"expected {name1} deleted (ParameterNotFound), got {code1}"
    assert message1 == "", f"GetParameter message for {name1}: {message1!r}"
    code2, message2 = _error(lambda: ssm.get_parameter(Name=name2))
    assert code2 == "ParameterNotFound", f"expected {name2} deleted (ParameterNotFound), got {code2}"
    assert message2 == "", f"GetParameter message for {name2}: {message2!r}"


def _delete_parameter_if_present(ssm, name: str) -> None:
    try:
        ssm.delete_parameter(Name=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ParameterNotFound":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
