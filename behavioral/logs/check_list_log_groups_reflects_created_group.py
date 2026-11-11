"""list-log-groups-reflects-created-group."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "list-log-groups-reflects-created-group"
GROUP = "state-machine"
SERVICES = ["logs"]


def _list_all_log_groups(logs, name_pattern):
    log_groups = []
    kwargs = {"logGroupNamePattern": name_pattern}
    while True:
        resp = logs.list_log_groups(**kwargs)
        log_groups.extend(resp.get("logGroups", []))
        next_token = resp.get("nextToken")
        if not next_token:
            return log_groups
        kwargs["nextToken"] = next_token


def _find_by_name(log_groups, name):
    for lg in log_groups:
        if lg["logGroupName"] == name:
            return lg
    return None


def _poll_until(fn, predicate, *, timeout_s, interval_s, message):
    import time

    deadline = time.monotonic() + timeout_s
    result = fn()
    while not predicate(result):
        if time.monotonic() >= deadline:
            raise AssertionError(f"{message}: last observed {result!r}")
        time.sleep(interval_s)
        result = fn()
    return result


def _delete_log_group(logs, name):
    """Teardown: delete the log group; ResourceNotFoundException means the body already deleted it."""
    try:
        logs.delete_log_group(logGroupName=name)
    except logs.exceptions.ResourceNotFoundException:
        return


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListLogGroups includes a newly created log group, and stops including it after deletion."""
    logs = ctx.client("logs")
    name = ctx.unique_name("sim2real-logs-listgroups-")

    create_resp = logs.create_log_group(logGroupName=name)
    ctx.on_cleanup(lambda: _delete_log_group(logs, name))
    assert create_resp["ResponseMetadata"]["HTTPStatusCode"] == 200, (
        f"expected 200 from CreateLogGroup, got {create_resp['ResponseMetadata']['HTTPStatusCode']}"
    )

    describe = logs.describe_log_groups(logGroupNamePrefix=name)
    expected_arn_prefix = describe["logGroups"][0]["logGroupArn"].rsplit(":", 1)[0]

    # ListLogGroups (unlike DescribeLogGroups) is not a paginated botocore operation and
    # filters by substring pattern rather than prefix; page through it manually. Its index is
    # also not guaranteed consistent with CreateLogGroup's own response the instant it returns
    # (confirmed on real AWS: an immediate, unretried list can miss a group that DescribeLogGroups
    # already reports), so poll bounded rather than asserting on the first read.
    found = _poll_until(
        lambda: _find_by_name(_list_all_log_groups(logs, name), name),
        lambda lg: lg is not None,
        timeout_s=60.0,
        interval_s=3.0,
        message=f"{name} never appeared in ListLogGroups",
    )
    assert found["logGroupClass"] == "STANDARD", (
        f"expected logGroupClass STANDARD, got {found['logGroupClass']!r}"
    )
    assert found["logGroupArn"].startswith(expected_arn_prefix), (
        f"expected ARN to start with {expected_arn_prefix!r}, got {found['logGroupArn']!r}"
    )

    # Delete and confirm ListLogGroups no longer surfaces it (the effect is observable both
    # ways, not just on creation); the same index lag means absence needs the same bounded poll.
    logs.delete_log_group(logGroupName=name)
    _poll_until(
        lambda: _find_by_name(_list_all_log_groups(logs, name), name),
        lambda lg: lg is None,
        timeout_s=60.0,
        interval_s=3.0,
        message=f"{name} still present in ListLogGroups after DeleteLogGroup",
    )

    # The deleted id is now unusable, not just absent from the listing.
    try:
        logs.delete_log_group(logGroupName=name)
    except logs.exceptions.ResourceNotFoundException as exc:
        message = exc.response["Error"]["Message"]
        assert message == "The specified log group does not exist.", (
            f"DeleteLogGroup on already-deleted {name} returned message {message!r}"
        )
    else:
        raise AssertionError(f"DeleteLogGroup on already-deleted {name} unexpectedly succeeded")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
