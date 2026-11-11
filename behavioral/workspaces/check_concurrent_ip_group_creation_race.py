"""concurrent-ip-group-creation-race."""
from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor

from behavioral_harness import tags

CHECK = "concurrent-ip-group-creation-race"
GROUP = "concurrency"
SERVICES = ["workspaces"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Of 8 concurrent CreateIpGroup calls sharing a GroupName, at least one succeeds and every rejected
    one fails with ResourceAlreadyExistsException and the exact message; exactly one group persists
    under the name, with one of the accepted GroupIds.
    """
    ws = ctx.client("workspaces")
    name = ctx.unique_name("sim2real-wsipg-race-")

    def attempt(_: int):
        from botocore.exceptions import ClientError

        try:
            return (
                "ok",
                ws.create_ip_group(
                    GroupName=name,
                    GroupDesc="race",
                    Tags=[{"Key": "sim2real-behav", "Value": "true"}],
                )["GroupId"],
            )
        except ClientError as e:
            return ("error", e.response["Error"]["Code"], e.response["Error"].get("Message"))

    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(attempt, range(8)))

    successes = [r[1] for r in results if r[0] == "ok"]
    failures = [r[1] for r in results if r[0] == "error"]

    # Register cleanup for every group this run actually created before asserting anything,
    # so a failed assertion below never leaks a created group.
    for created_id in successes:
        ctx.on_cleanup(lambda gid=created_id: _safe_delete_ip_group(ctx, gid))

    assert len(successes) + len(failures) == 8, f"expected 8 outcomes, got {results}"
    assert successes, "expected at least one winner, got none"
    assert all(code == "ResourceAlreadyExistsException" for code in failures), (
        f"every rejected attempt must be ResourceAlreadyExistsException, got {failures}"
    )
    expected_message = (
        "Encountered an exception while creating IP Group - group already exists for given "
        f"group name - {name}"
    )
    rejected_messages = [r[2] for r in results if r[0] == "error"]
    assert all(m == expected_message for m in rejected_messages), (
        f"every rejected attempt must carry {expected_message!r}, got {rejected_messages}"
    )

    # Independent terminal read: regardless of how many 200s the race produced, exactly one
    # group ends up persisted under the shared name, and it is one of the accepted GroupIds --
    # the rest of `successes` were phantom accepts that never became real. A bounded retry
    # covers list-view settle time right after the writes; it is not a barrier for absence.
    matching: list[dict] = []
    for _ in range(10):
        all_groups: list[dict] = []
        token = None
        while True:
            resp = ws.describe_ip_groups(**({"NextToken": token} if token else {}))
            all_groups.extend(resp.get("Result", []))
            token = resp.get("NextToken")
            if not token:
                break
        matching = [g for g in all_groups if g.get("groupName") == name]
        if len(matching) == 1:
            break
        time.sleep(2)

    assert len(matching) == 1, f"expected exactly one persisted group named {name!r}, got {matching}"
    assert matching[0]["groupId"] in successes, (
        f"persisted GroupId {matching[0]['groupId']!r} is not among the accepted ids {successes}"
    )


def _safe_delete_ip_group(ctx, group_id: str) -> None:
    from botocore.exceptions import ClientError

    ws = ctx.client("workspaces")
    try:
        ws.delete_ip_group(GroupId=group_id)
    except ClientError as e:
        if e.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
