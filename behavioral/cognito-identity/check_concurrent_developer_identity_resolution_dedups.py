"""concurrent-developer-identity-resolution-dedups."""
from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor, as_completed

from behavioral_harness import tags

CHECK = "concurrent-developer-identity-resolution-dedups"
GROUP = "concurrency"
SERVICES = ["cognito-identity"]


def _list_identities(ci, pool_id):
    """Every identity in the pool, paginated."""
    ids = set()
    next_token = None
    pages = 0
    while True:
        kwargs = {"IdentityPoolId": pool_id, "MaxResults": 60}
        if next_token:
            kwargs["NextToken"] = next_token
        resp = ci.list_identities(**kwargs)
        ids.update(i["IdentityId"] for i in resp.get("Identities", []))
        next_token = resp.get("NextToken")
        pages += 1
        if not next_token or pages > 50:
            return ids


def _settled_identities(ci, pool_id, baseline, timeout_s=90.0, interval_s=5.0):
    """The pool's identity set once ListIdentities has stopped changing -- it is eventually
    consistent after a burst of creates, so "the pool gained exactly one" can only be asserted
    against a listing that repeated itself."""
    deadline = time.time() + timeout_s
    previous = None
    while time.time() < deadline:
        current = _list_identities(ci, pool_id)
        if current - baseline and current == previous:
            return current
        previous = current
        time.sleep(interval_s)
    raise AssertionError(
        f"identity listing never settled within {timeout_s}s: last two readings were "
        f"{sorted(previous or [])!r} and {sorted(_list_identities(ci, pool_id))!r}"
    )


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Concurrent GetOpenIdTokenForDeveloperIdentity calls for one new developer user identifier all resolve to a
    single IdentityId, and ListIdentities shows only that one new identity in the pool.
    """
    ci = ctx.client("cognito-identity")
    dev_provider = ctx.unique_name("sim2real-dev-")
    pool_id = ci.create_identity_pool(
        IdentityPoolName=ctx.unique_name("sim2real-behav-"),
        AllowUnauthenticatedIdentities=True,
        DeveloperProviderName=dev_provider,
        IdentityPoolTags={"sim2real": CHECK},
    )["IdentityPoolId"]
    ctx.on_cleanup(lambda: ci.delete_identity_pool(IdentityPoolId=pool_id))

    baseline = _list_identities(ci, pool_id)
    dev_user = ctx.unique_name("racer-user-")
    n_racers = 8

    def register() -> str:
        return ci.get_open_id_token_for_developer_identity(
            IdentityPoolId=pool_id, Logins={dev_provider: dev_user}
        )["IdentityId"]

    with ThreadPoolExecutor(max_workers=n_racers) as pool:
        futures = [pool.submit(register) for _ in range(n_racers)]
        resolved_ids = [f.result() for f in as_completed(futures)]

    assert len(resolved_ids) == n_racers, (
        f"expected {n_racers} concurrent registrations to complete, got {len(resolved_ids)}"
    )
    unique_ids = set(resolved_ids)
    ctx.on_cleanup(lambda: ci.delete_identities(IdentityIdsToDelete=list(unique_ids)))
    assert len(unique_ids) == 1, (
        f"expected all {n_racers} racers to dedup onto one identity, got {len(unique_ids)}: {unique_ids}"
    )

    settled = _settled_identities(ci, pool_id, baseline)
    new_ids = settled - baseline
    assert new_ids == unique_ids, (
        f"the pool gained {sorted(new_ids)!r} but the callers were told {sorted(unique_ids)!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
