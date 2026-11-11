"""list-policies-pagination-returns-all."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "list-policies-pagination-returns-all"
GROUP = "control-plane"
SERVICES = ["verifiedpermissions"]


@tags("axis:happy-path", "cap:c2", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListPolicies with a small maxResults pages through nextToken and the
    union of all pages exactly equals the full set of created policies, with
    no duplicates and no omissions."""
    client = ctx.client("verifiedpermissions")
    store_id = _create_policy_store(ctx, client)
    created_ids = set()
    for i in range(5):
        statement = (
            f'permit(principal == User::"user{i}", action == Action::"viewPhoto", '
            f'resource == Photo::"photo{i}.jpg");'
        )
        policy_id = client.create_policy(
            policyStoreId=store_id, definition={"static": {"statement": statement}}
        )["policyId"]
        created_ids.add(policy_id)

    seen_ids = []
    next_token = None
    pages = 0
    while True:
        kwargs = {"policyStoreId": store_id, "maxResults": 2}
        if next_token:
            kwargs["nextToken"] = next_token
        page = client.list_policies(**kwargs)
        pages += 1
        seen_ids.extend(p["policyId"] for p in page["policies"])
        next_token = page.get("nextToken")
        if not next_token or pages > 20:
            break

    assert pages >= 3, f"expected pagination across multiple pages, got {pages}"
    assert len(seen_ids) == len(set(seen_ids)), "duplicate policy returned across pages"
    assert set(seen_ids) == created_ids, (
        f"expected paginated union to equal created policies {created_ids}, got {set(seen_ids)}"
    )


def _create_policy_store(ctx, client, mode: str = "OFF") -> str:
    store_id = client.create_policy_store(
        validationSettings={"mode": mode}, tags={"sim2real": CHECK}
    )["policyStoreId"]
    ctx.on_cleanup(lambda: client.delete_policy_store(policyStoreId=store_id))
    return store_id


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
