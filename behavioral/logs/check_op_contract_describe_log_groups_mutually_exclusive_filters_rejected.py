"""op-contract-describe-log-groups-mutually-exclusive-filters-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-describe-log-groups-mutually-exclusive-filters-rejected"
GROUP = "error-semantics"
SERVICES = ["logs"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeLogGroups lists the created group by prefix with its arn, creationTime and zero
    storedBytes, and refuses logGroupNamePrefix combined with logGroupNamePattern with
    InvalidParameterException and its exact message.
    """
    logs = ctx.client("logs")
    group_name = ctx.unique_name("sim2real-behav-lg-")

    logs.create_log_group(logGroupName=group_name)
    ctx.on_cleanup(lambda: logs.delete_log_group(logGroupName=group_name))

    resp = logs.describe_log_groups(logGroupNamePrefix=group_name)
    groups = resp["logGroups"]
    assert len(groups) == 1, f"expected exactly 1 log group, got {len(groups)}"
    group = groups[0]
    assert group["logGroupName"] == group_name, (
        f"expected logGroupName {group_name!r}, got {group['logGroupName']!r}"
    )
    assert "arn" in group and group_name in group["arn"], (
        f"expected an arn containing {group_name!r}, got {group.get('arn')!r}"
    )
    assert "creationTime" in group, f"expected a creationTime field, got {group!r}"
    assert group.get("storedBytes", 0) == 0, (
        f"expected storedBytes 0 for a freshly created empty log group, got {group.get('storedBytes')!r}"
    )

    # Prefix and pattern together must be rejected.
    code, message = _error(
        lambda: logs.describe_log_groups(
            logGroupNamePrefix=group_name, logGroupNamePattern=group_name
        )
    )
    assert code == "InvalidParameterException", f"expected InvalidParameterException, got {code}"
    assert message == (
        "LogGroup name prefix and LogGroup name pattern are mutually exclusive parameters."
    ), f"unexpected message: {message!r}"


def _error(fn):
    """Call fn(); return its botocore error Code. An unexpected SUCCESS raises, because an emulator
    ACCEPTING input real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(
        f"real AWS rejects logGroupNamePrefix+logGroupNamePattern together, but it SUCCEEDED "
        f"and returned {result!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
