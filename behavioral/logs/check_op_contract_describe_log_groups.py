"""op-contract-describeLogGroups."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "op-contract-describeLogGroups"
GROUP = "error-semantics"
SERVICES = ["logs"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeLogGroups returns the created group with its name, zero storedBytes and its ARN, and
    refuses logGroupIdentifiers combined with logGroupNamePrefix with InvalidParameterException.
    """
    logs = ctx.client("logs")
    group_name = ctx.unique_name("sim2real-behav-dlgs-")

    logs.create_log_group(
        logGroupName=group_name, tags={"Sim2RealOwner": "behavioral-suite"}
    )
    ctx.on_cleanup(lambda: logs.delete_log_group(logGroupName=group_name))

    groups = logs.describe_log_groups(logGroupNamePrefix=group_name)["logGroups"]
    assert len(groups) == 1, f"expected exactly one group, got {groups}"
    group = groups[0]
    assert group["logGroupName"] == group_name, f"got {group['logGroupName']!r}"
    assert group.get("storedBytes", 0) == 0, f"got {group.get('storedBytes')!r}"
    assert group["arn"].endswith(f"log-group:{group_name}:*"), f"got {group['arn']!r}"
    group_arn = group["logGroupArn"]

    code, message = _error(
        lambda: logs.describe_log_groups(
            logGroupIdentifiers=[group_arn], logGroupNamePrefix=group_name
        )
    )
    assert code == "InvalidParameterException", f"got {code!r}"
    assert message == (
        "No other input filter parameter can be provided with LogGroupIdentifiers"
    ), f"unexpected message: {message!r}"


def _error(fn):
    """Call fn(); return its botocore error code. An unexpected SUCCESS raises, because an emulator
    ACCEPTING input real AWS refuses is the strongest signal available."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
