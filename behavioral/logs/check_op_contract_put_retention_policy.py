"""op-contract-putRetentionPolicy."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-putRetentionPolicy"
GROUP = "error-semantics"
SERVICES = ["logs"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutRetentionPolicy sets and updates retentionInDays, DeleteRetentionPolicy removes it, and a
    value outside the allowed set is rejected with InvalidParameterException and not applied.
    """
    logs = ctx.client("logs")
    group_name = ctx.unique_name("sim2real-behav-lg-")
    logs.create_log_group(logGroupName=group_name, tags={"Sim2RealOwner": "behavioral-suite"})
    ctx.on_cleanup(lambda: logs.delete_log_group(logGroupName=group_name))

    logs.put_retention_policy(logGroupName=group_name, retentionInDays=7)
    described = logs.describe_log_groups(logGroupNamePrefix=group_name)
    matches = [g for g in described["logGroups"] if g["logGroupName"] == group_name]
    assert len(matches) == 1, f"expected exactly one log group, got {matches}"
    assert matches[0]["retentionInDays"] == 7, matches[0]

    logs.put_retention_policy(logGroupName=group_name, retentionInDays=14)
    described2 = logs.describe_log_groups(logGroupNamePrefix=group_name)
    match2 = [g for g in described2["logGroups"] if g["logGroupName"] == group_name][0]
    assert match2["retentionInDays"] == 14, match2

    # DeleteRetentionPolicy removes the field entirely (never expires).
    logs.delete_retention_policy(logGroupName=group_name)
    described3 = logs.describe_log_groups(logGroupNamePrefix=group_name)
    match3 = [g for g in described3["logGroups"] if g["logGroupName"] == group_name][0]
    assert "retentionInDays" not in match3, match3

    code, message = _client_error(
        lambda: logs.put_retention_policy(logGroupName=group_name, retentionInDays=13)
    )
    assert code == "InvalidParameterException", f"expected InvalidParameterException, got {code}"
    assert message == (
        "Invalid retention value. Valid values are: [1, 3, 5, 7, 14, 30, 60, 90, 120, 150, 180, "
        "365, 400, 545, 731, 1096, 1827, 2192, 2557, 2922, 3288, 3653]"
    ), f"unexpected message: {message!r}"

    described4 = logs.describe_log_groups(logGroupNamePrefix=group_name)
    match4 = [g for g in described4["logGroups"] if g["logGroupName"] == group_name][0]
    assert "retentionInDays" not in match4, (
        f"rejected PutRetentionPolicy(retentionInDays=13) was partially applied: {match4}"
    )


def _client_error(fn):
    """Call fn(); return its (code, message). An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
