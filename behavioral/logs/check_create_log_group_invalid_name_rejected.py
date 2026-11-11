"""create-log-group-invalid-name-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags


def _error(fn):
    """Call fn() and return the (code, message) of the ClientError it raises; a success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


CHECK = "create-log-group-invalid-name-rejected"
GROUP = 'log-group-lifecycle'
SERVICES = ['logs']


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """OVERLY-PERMISSIVE: CreateLogGroup must reject a name containing characters
    outside the documented allowed set, not silently sanitize it. A positive control
    proves the same operation succeeds for a valid name in this account."""
    svc = ctx.client("logs")
    prefix = "sim2real-behav-lg-invalid"
    invalid_name = f"{prefix} !!! {ctx.unique_name('')}"

    code, msg = _error(lambda: svc.create_log_group(logGroupName=invalid_name))
    assert code == "InvalidParameterException", f"expected InvalidParameterException, got {code!r} {msg!r}"
    assert msg == (
        "1 validation error detected: Value at 'logGroupName' failed to satisfy constraint: "
        "Member must satisfy regular expression pattern: [\\.\\-_/#A-Za-z0-9]+"
    ), f"unexpected message: {msg!r}"

    desc = svc.describe_log_groups(logGroupNamePrefix=prefix)
    assert desc.get("logGroups", []) == [], "invalid-name log group was created anyway"

    valid_name = ctx.unique_name("sim2real-behav-lg-invalid-ok-")
    svc.create_log_group(logGroupName=valid_name)
    ctx.on_cleanup(lambda: svc.delete_log_group(logGroupName=valid_name))
    desc_valid = svc.describe_log_groups(logGroupNamePrefix=valid_name)
    valid_names = [g["logGroupName"] for g in desc_valid.get("logGroups", [])]
    assert valid_name in valid_names, (
        f"expected {valid_name!r} to exist after CreateLogGroup (positive control), found {valid_names}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
