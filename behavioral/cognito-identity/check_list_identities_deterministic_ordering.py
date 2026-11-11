"""list-identities-deterministic-ordering."""
from __future__ import annotations

import time
from typing import Any, Callable

from behavioral_harness import tags

CHECK = "list-identities-deterministic-ordering"
GROUP = "ordering"
SERVICES = ["cognito-identity"]


@tags("axis:happy-path", "cap:c2", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Repeated ListIdentities calls against an unchanged pool return identities in stable order."""
    client = ctx.client("cognito-identity")
    pool_id = _create_pool(ctx, client)

    created_ids = [client.get_id(IdentityPoolId=pool_id)["IdentityId"] for _ in range(5)]

    def probe() -> dict[str, Any]:
        return client.list_identities(IdentityPoolId=pool_id, MaxResults=60)

    def predicate(resp: dict[str, Any]) -> bool:
        seen = {i["IdentityId"] for i in resp.get("Identities", [])}
        return set(created_ids).issubset(seen)

    resp1 = _poll_until(probe, predicate, timeout_s=30.0, interval_s=2.0)
    order1 = [i["IdentityId"] for i in resp1["Identities"]]
    order2 = [i["IdentityId"] for i in client.list_identities(IdentityPoolId=pool_id, MaxResults=60)["Identities"]]
    order3 = [i["IdentityId"] for i in client.list_identities(IdentityPoolId=pool_id, MaxResults=60)["Identities"]]

    assert set(created_ids).issubset(set(order1)), "created identities missing from ListIdentities"
    assert order1 == order2 == order3, (
        f"ListIdentities order changed across repeated calls: {order1!r} vs {order2!r} vs {order3!r}"
    )


def _create_pool(ctx, client, **extra_fields: Any) -> str:
    params = {
        "IdentityPoolName": ctx.unique_name("sim2real-idp-"),
        "AllowUnauthenticatedIdentities": True,
        "IdentityPoolTags": {"sim2real": CHECK},
    }
    params.update(extra_fields)
    pool_id = client.create_identity_pool(**params)["IdentityPoolId"]
    ctx.on_cleanup(lambda: client.delete_identity_pool(IdentityPoolId=pool_id))
    return pool_id


def _poll_until(
    probe: Callable[[], Any],
    predicate: Callable[[Any], bool],
    *,
    timeout_s: float = 30.0,
    interval_s: float = 2.0,
) -> Any:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
