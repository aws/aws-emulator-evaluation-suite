"""concurrent-create-policy-store-alias-race."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "concurrent-create-policy-store-alias-race"
GROUP = "concurrency"
SERVICES = ["verifiedpermissions"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Racing CreatePolicyStoreAlias calls that claim one alias name for different policy stores yield
    exactly one winner and ConflictException with the exact message for every other racer, and the alias
    resolves Active to the winner's store."""
    client = ctx.client("verifiedpermissions")
    racer_count = 8
    store_ids = [_create_policy_store(ctx, client) for _ in range(racer_count)]
    alias_name = "policy-store-alias/" + ctx.unique_name("sim2real-behav-aliasrace-")

    # The winner's alias is removed even when an assert below fails; a missing alias is fine.
    ctx.on_cleanup(lambda: _delete_alias_if_present(client, alias_name))

    def attempt(store_id: str):
        try:
            resp = client.create_policy_store_alias(aliasName=alias_name, policyStoreId=store_id)
            return ("ok", store_id, resp["policyStoreId"])
        except ClientError as exc:
            err = exc.response["Error"]
            return ("error", store_id, (err["Code"], err.get("Message")))

    outcomes = []
    with ThreadPoolExecutor(max_workers=racer_count) as pool:
        futures = [pool.submit(attempt, sid) for sid in store_ids]
        for future in as_completed(futures):
            outcomes.append(future.result())

    successes = [o for o in outcomes if o[0] == "ok"]
    failures = [o for o in outcomes if o[0] == "error"]
    assert len(successes) == 1, f"expected exactly 1 winner, got successes={successes} failures={failures}"
    assert len(failures) == racer_count - 1, (
        f"expected {racer_count - 1} losers, got {len(failures)}: {failures}"
    )
    expected_error = ("ConflictException", "Conflict occurred during the processing of this request")
    assert all(error == expected_error for _, _, error in failures), (
        f"expected every loser to fail with {expected_error!r}, got {failures}"
    )

    winning_store_id = successes[0][2]
    alias_info = client.get_policy_store_alias(aliasName=alias_name)
    assert alias_info["policyStoreId"] == winning_store_id, (
        f"expected alias to resolve to the winning store {winning_store_id!r}, "
        f"got {alias_info['policyStoreId']!r}"
    )
    assert alias_info["state"] == "Active", f"expected state Active, got {alias_info['state']!r}"


def _create_policy_store(ctx, client, mode: str = "OFF") -> str:
    store_id = client.create_policy_store(validationSettings={"mode": mode})["policyStoreId"]
    ctx.on_cleanup(lambda: client.delete_policy_store(policyStoreId=store_id))
    return store_id


def _delete_alias_if_present(client, alias_name: str) -> None:
    try:
        client.delete_policy_store_alias(aliasName=alias_name, deletionMode="HardDelete")
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

