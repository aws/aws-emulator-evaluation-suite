"""describe-instance-patches-invalid-instance-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "describe-instance-patches-invalid-instance-rejected"
GROUP = "overly-permissive"
SERVICES = ["ssm"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DescribeInstancePatches with an InstanceId that breaks the length and pattern constraints fails
    with the exact two-error ValidationException, while GetParameter on the check's parameter still
    answers before and after."""
    ssm = ctx.client("ssm")

    # Positive control: an ordinary parameter round trip proves the client/creds work.
    param_name = ctx.unique_name("/sim2real-behav/instpatch-control-")
    ssm.put_parameter(Name=param_name, Value="control", Type="String")
    ctx.on_cleanup(lambda: ssm.delete_parameter(Name=param_name))
    control = ssm.get_parameter(Name=param_name)
    assert control["Parameter"]["Value"] == "control", control["Parameter"]["Value"]

    # Negative: a malformed instance id (fails the i-/mi- pattern entirely).
    bogus_instance_id = "sim2real-behav-not-an-instance-id"
    code, message = _error(lambda: ssm.describe_instance_patches(InstanceId=bogus_instance_id))
    assert code == "ValidationException", code
    assert message == (
        f"2 validation errors detected: Value '{bogus_instance_id}' at 'instanceId' failed to satisfy "
        "constraint: Member must have length less than or equal to 20; "
        f"Value '{bogus_instance_id}' at 'instanceId' failed to satisfy constraint: "
        r"Member must satisfy regular expression pattern: (^i-(\w{8}|\w{17})$)|(^mi-\w{17}$)"
    ), message

    # The control still works after the failed call (effect absent / no side state).
    still_ok = ssm.get_parameter(Name=param_name)
    assert still_ok["Parameter"]["Value"] == "control", still_ok["Parameter"]["Value"]


def _error(fn):
    """Call fn(); return its error (code, message). An unexpected SUCCESS raises, so an
    emulator that accepts what AWS refuses cannot read as a code mismatch."""
    try:
        result = fn()
    except ClientError as err:
        error = err.response["Error"]
        return error["Code"], error.get("Message", "")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
