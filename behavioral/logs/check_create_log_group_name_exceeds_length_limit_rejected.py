"""create-log-group-name-exceeds-length-limit-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-log-group-name-exceeds-length-limit-rejected"
GROUP = "error-semantics"
SERVICES = ["logs"]

# logGroupName has a max length of 512 characters per the CreateLogGroup shape.
_MAX_NAME_LEN = 512


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateLogGroup rejects a name exceeding the 512-character length limit, the
    group is never created, and a normal-length name still succeeds."""
    logs = ctx.client("logs")
    prefix = ctx.unique_name("sim2real-behav-cgnl-")
    too_long_name = prefix + ("g" * (_MAX_NAME_LEN + 1 - len(prefix)))
    assert len(too_long_name) == _MAX_NAME_LEN + 1

    code, msg = _error(lambda: logs.create_log_group(logGroupName=too_long_name))
    assert code == "InvalidParameterException", f"expected InvalidParameterException, got {code!r} {msg!r}"
    assert msg == "Invalid LogGroup or LogStream, both must have length less than or equal to 512.", (
        f"unexpected message: {msg!r}"
    )

    # (b) effect absent: nothing under this prefix exists at all -- not just the
    # over-long name itself
    resp = logs.describe_log_groups(logGroupNamePrefix=prefix)
    names = [g["logGroupName"] for g in resp.get("logGroups", [])]
    assert names == [], f"expected no log groups created under prefix, found {names}"

    # (c) positive control: a valid-length name is accepted
    valid_name = prefix + "ok"
    logs.create_log_group(logGroupName=valid_name, tags={"Sim2RealOwner": "behavioral-suite"})
    ctx.on_cleanup(lambda: logs.delete_log_group(logGroupName=valid_name))
    resp = logs.describe_log_groups(logGroupNamePrefix=valid_name)
    names = [g["logGroupName"] for g in resp.get("logGroups", [])]
    assert valid_name in names


def _error(fn):
    """Call fn() and return the (code, message) of the ClientError it raises; a success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
