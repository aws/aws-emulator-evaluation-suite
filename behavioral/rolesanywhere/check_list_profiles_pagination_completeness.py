"""list-profiles-pagination-completeness."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "list-profiles-pagination-completeness"
GROUP = "data-plane"
SERVICES = ["rolesanywhere"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Paging ListProfiles one item at a time via nextToken visits every
    created profile exactly once (no duplicates, no misses)."""
    ra = ctx.client("rolesanywhere")
    account_id = ctx.client("sts").get_caller_identity()["Account"]

    profile_ids = []
    for _ in range(3):
        # roleArns must be unique across all profiles in the account, so each
        # profile in this loop gets its own distinct (non-existent, but
        # syntactically valid) role ARN.
        role_arn = f"arn:aws:iam::{account_id}:role/{ctx.unique_name('sim2real-ra-role-')}"
        created = ra.create_profile(
            name=ctx.unique_name("sim2real-ra-page-profile-"),
            roleArns=[role_arn],
            tags=[{"key": "sim2real", "value": "true"}],
        )["profile"]
        profile_ids.append(created["profileId"])
        ctx.on_cleanup(lambda pid=created["profileId"]: ra.delete_profile(profileId=pid))

    seen = {}
    next_token = None
    while True:
        kwargs = {"nextToken": next_token, "pageSize": 1} if next_token else {"pageSize": 1}
        resp = ra.list_profiles(**kwargs)
        page = resp.get("profiles", [])
        assert len(page) <= 1, f"expected pageSize=1 to yield at most 1 profile, got {len(page)}"
        for entry in page:
            seen[entry["profileId"]] = seen.get(entry["profileId"], 0) + 1
        next_token = resp.get("nextToken")
        if not next_token:
            break

    for pid in profile_ids:
        assert seen.get(pid) == 1, (
            f"expected profile {pid} to be visited exactly once across pages, "
            f"got {seen.get(pid, 0)} times"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
