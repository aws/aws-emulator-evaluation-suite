"""describe-log-groups-pagination-no-duplicates."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "describe-log-groups-pagination-no-duplicates"
GROUP = 'log-group-lifecycle'
SERVICES = ['logs']

def _create_log_group(ctx, logs, name=None, **kwargs) -> str:
    name = name or ctx.unique_name("sim2real-behav-lg-")
    logs.create_log_group(logGroupName=name, **kwargs)
    ctx.on_cleanup(lambda: _delete_log_group(logs, name))
    return name


def _delete_log_group(logs, name) -> None:
    """Drop deletion protection (if any) before deleting, mirroring the suite's teardown."""
    try:
        logs.put_log_group_deletion_protection(
            logGroupIdentifier=name, deletionProtectionEnabled=False
        )
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise
    logs.delete_log_group(logGroupName=name)

@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeLogGroups with limit=1 must page through every group exactly once via nextToken."""
    logs = ctx.client("logs")
    prefix = ctx.unique_name("sim2real-behav-lg-page-")
    created = [_create_log_group(ctx, logs, f"{prefix}-{i}") for i in range(3)]

    seen: list[str] = []
    token = None
    pages = 0
    for _ in range(10):
        kwargs = {"logGroupNamePrefix": prefix, "limit": 1}
        if token:
            kwargs["nextToken"] = token
        resp = logs.describe_log_groups(**kwargs)
        pages += 1
        assert len(resp.get("logGroups", [])) <= 1, (
            f"limit=1 must cap each page at 1 group, got {len(resp.get('logGroups', []))}"
        )
        seen.extend(g["logGroupName"] for g in resp.get("logGroups", []))
        token = resp.get("nextToken")
        if not token:
            break

    assert pages >= len(created), (
        f"expected pagination across >= {len(created)} pages with limit=1, got {pages}"
    )
    assert sorted(seen) == sorted(created), f"pagination lost or duplicated groups: {seen}"
    assert len(seen) == len(set(seen)), f"pagination returned duplicates: {seen}"

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
