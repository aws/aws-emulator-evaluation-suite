"""deep-cwlogs-semantics-retention-zero-rejected-and-unset-retention-absent."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deep-cwlogs-semantics-retention-zero-rejected-and-unset-retention-absent"
GROUP = "retention"
SERVICES = ["logs"]

_MISSING = object()
_INVALID_RETENTION = (
    "Invalid retention value. Valid values are: [1, 3, 5, 7, 14, 30, 60, 90, 120, 150, 180, 365, "
    "400, 545, 731, 1096, 1827, 2192, 2557, 2922, 3288, 3653]"
)


@tags(
    "axis:rejection",
    "cap:c1",
    "concern:negative-classes",
    "concern:representation",
    "plane:control",
)
def run(ctx) -> None:
    """Never-expire is the absence of ``retentionInDays``, never 0: a fresh group omits the key, and
    PutRetentionPolicy(retentionInDays=0) is refused InvalidParameterException and changes nothing,
    both while unset and with a policy set; DeleteRetentionPolicy returns the key to absent."""
    logs = ctx.client("logs")
    group = ctx.unique_name("sim2real-behav-lg-ret0-")
    logs.create_log_group(logGroupName=group, tags={"sim2real-check": CHECK})
    ctx.on_cleanup(lambda: logs.delete_log_group(logGroupName=group))

    def retention():
        entry = _describe(logs, group)
        return entry.get("retentionInDays", _MISSING), entry

    value, entry = retention()
    assert value is _MISSING, (
        "a log group that never had a retention policy must OMIT retentionInDays (absent, "
        f"not 0 and not null); DescribeLogGroups returned {entry!r}"
    )

    # The model types Days as a bare integer; the legal set is documented only.
    code, message = _error_code(lambda: logs.put_retention_policy(logGroupName=group, retentionInDays=0))
    assert code == "InvalidParameterException", (
        f"PutRetentionPolicy(retentionInDays=0) must be refused with InvalidParameterException, got {code!r}"
    )
    assert message == _INVALID_RETENTION, f"unexpected retentionInDays=0 refusal message: {message!r}"
    value, entry = retention()
    assert value is _MISSING, (
        f"a refused retentionInDays=0 must leave retention absent; DescribeLogGroups returned {entry!r}"
    )

    # Positive control: the smallest legal value is accepted and read back.
    logs.put_retention_policy(logGroupName=group, retentionInDays=1)
    value, entry = retention()
    assert value == 1, f"PutRetentionPolicy(1) must read back as 1; DescribeLogGroups returned {entry!r}"

    code, message = _error_code(lambda: logs.put_retention_policy(logGroupName=group, retentionInDays=0))
    assert code == "InvalidParameterException", (
        "retentionInDays=0 must be refused with InvalidParameterException even when a policy "
        f"is set (it is not a way to clear it); got {code!r}"
    )
    assert message == _INVALID_RETENTION, (
        f"unexpected retentionInDays=0 refusal message with a policy set: {message!r}"
    )
    value, entry = retention()
    assert value == 1, (
        f"a refused retentionInDays=0 must leave the existing policy at 1; DescribeLogGroups returned {entry!r}"
    )

    logs.delete_retention_policy(logGroupName=group)
    value, entry = retention()
    assert value is _MISSING, (
        f"DeleteRetentionPolicy must return the group to ABSENT retention, not 0; got {entry!r}"
    )


def _error_code(fn) -> tuple[str, str]:
    """The AWS error (code, message). An unexpected SUCCESS raises rather than returning a falsy value."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"real AWS refuses this call, but it SUCCEEDED and returned {result!r}")


def _describe(logs, group) -> dict:
    """The exact DescribeLogGroups entry for ``group``, paginated (the prefix is unique)."""
    for page in logs.get_paginator("describe_log_groups").paginate(logGroupNamePrefix=group):
        for g in page["logGroups"]:
            if g["logGroupName"] == group:
                return g
    raise AssertionError(f"log group {group!r} is missing from DescribeLogGroups")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
