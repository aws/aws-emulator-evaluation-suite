"""create-log-group-name-exceeds-max-length-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-log-group-name-exceeds-max-length-rejected"
GROUP = "error-semantics"
SERVICES = ["logs"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateLogGroup rejects a name that is 1 character longer than the documented 512-char
    maximum with InvalidParameterException, the group is never created, while a name that is
    well within the limit succeeds (positive control)."""
    logs = ctx.client("logs")
    valid_prefix = ctx.unique_name("sim2real-lgmax-")

    # A name using only allowed characters ([\.\-_/#A-Za-z0-9]) but 513 characters long --
    # one over the documented 512-character maximum for logGroupName.
    too_long_name = (valid_prefix + "a" * 600)[:513]
    assert len(too_long_name) == 513

    code, msg = _error(lambda: logs.create_log_group(logGroupName=too_long_name))
    assert code == "InvalidParameterException", f"expected InvalidParameterException, got {code!r} {msg!r}"
    assert msg == "Invalid LogGroup or LogStream, both must have length less than or equal to 512.", (
        f"unexpected message: {msg!r}"
    )

    # Effect absent: no log group with that (or any matching-prefix) name exists.
    listing = logs.describe_log_groups(logGroupNamePrefix=valid_prefix)
    names = [g["logGroupName"] for g in listing["logGroups"]]
    assert too_long_name not in names
    assert names == [], f"expected no log groups created under prefix, found {names}"

    # Positive control: a valid-length name (well under 512 chars) succeeds.
    valid_name = valid_prefix + "ok"
    logs.create_log_group(logGroupName=valid_name, tags={"Sim2RealOwner": "behavioral-suite"})
    ctx.on_cleanup(lambda: logs.delete_log_group(logGroupName=valid_name))

    listing2 = logs.describe_log_groups(logGroupNamePrefix=valid_prefix)
    names2 = [g["logGroupName"] for g in listing2["logGroups"]]
    assert valid_name in names2, f"expected {valid_name} to exist, found {names2}"


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
