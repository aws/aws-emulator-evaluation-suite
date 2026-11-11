"""concurrent-create-group-duplicate-name-race."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "concurrent-create-group-duplicate-name-race"
GROUP = "concurrency"
SERVICES = ["xray"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Two simultaneous CreateGroup calls with the identical GroupName resolve to exactly
    one success and one duplicate-name rejection, and exactly one group with that name
    ends up persisted."""
    xray = ctx.client("xray")
    group_name = ctx.unique_name("sim2real-behav-")
    ctx.on_cleanup(lambda: _delete_group_if_exists(xray, group_name))

    def _create(_index: int):
        try:
            resp = xray.create_group(GroupName=group_name, FilterExpression="duration >= 0")
            return ("ok", resp["Group"]["GroupARN"])
        except ClientError as exc:
            return ("error", exc.response["Error"]["Code"], exc.response["Error"].get("Message"))

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(_create, range(2)))

    outcomes = [r[0] for r in results]
    codes = [r[1] for r in results]
    assert outcomes.count("ok") == 1, f"expected exactly one success, outcomes={outcomes} codes={codes}"
    assert outcomes.count("error") == 1, f"expected exactly one rejection, outcomes={outcomes} codes={codes}"
    error_result = next(r for r in results if r[0] == "error")
    assert error_result[1] == "InvalidRequestException", f"unexpected error code: {error_result[1]}"
    assert error_result[2] == f"{group_name} already exists", f"unexpected message: {error_result[2]!r}"

    matching = [g for g in _all_groups(xray) if g["GroupName"] == group_name]
    assert len(matching) == 1, f"expected exactly one group named {group_name!r}, found {matching}"


# ===== helpers =====

def _all_groups(xray, max_pages: int = 25) -> list[dict]:
    """Every Group in the account, following NextToken -- GetGroups is paginated and the
    account may hold other groups, so a single unpaginated page can miss the
    group this check just created."""
    groups: list[dict] = []
    token = None
    for _ in range(max_pages):
        page = xray.get_groups(**({"NextToken": token} if token else {}))
        groups.extend(page.get("Groups", []))
        token = page.get("NextToken")
        if not token:
            break
    return groups


def _delete_group_if_exists(xray, group_name: str) -> None:
    """Teardown: a group that is already gone is clean; any other refusal is a failure."""
    try:
        xray.delete_group(GroupName=group_name)
    except ClientError as exc:
        err = exc.response.get("Error", {})
        if (err.get("Code"), err.get("Message")) != ("InvalidRequestException", "Group not found"):
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
