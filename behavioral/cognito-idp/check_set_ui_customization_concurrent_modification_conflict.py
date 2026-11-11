"""set-ui-customization-concurrent-modification-conflict."""
from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor

from behavioral_harness import tags

CHECK = "set-ui-customization-concurrent-modification-conflict"
GROUP = "concurrency"
SERVICES = ["cognito-idp"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Two concurrent SetUICustomization writes with different CSS leave GetUICustomization returning
    exactly one of the two payloads, and the same one on a second read."""
    cognito = ctx.client("cognito-idp")
    pool_id = _create_user_pool(ctx, cognito)
    client_id = cognito.create_user_pool_client(
        UserPoolId=pool_id, ClientName=ctx.unique_name("sim2real-behav-client-")
    )["UserPoolClient"]["ClientId"]

    domain = ctx.unique_name("sim2real-behav-domain-").lower()
    cognito.create_user_pool_domain(Domain=domain, UserPoolId=pool_id)

    def _domain_status():
        return cognito.describe_user_pool_domain(Domain=domain)["DomainDescription"].get("Status")

    def _delete_domain_and_wait():
        cognito.delete_user_pool_domain(Domain=domain, UserPoolId=pool_id)
        # DeleteUserPoolDomain is asynchronous -- DeleteUserPool fails while the domain is
        # still detaching, so the pool cleanup (which runs next, LIFO) would silently leak.
        _poll_until(_domain_status, lambda status: status is None, timeout_s=45.0, interval_s=3.0)

    ctx.on_cleanup(_delete_domain_and_wait)

    _poll_until(_domain_status, lambda status: status == "ACTIVE", timeout_s=180.0, interval_s=5.0)

    css_a = ".background-customizable { background-color: #101010; }"
    css_b = ".background-customizable { background-color: #202020; }"

    def _set(css):
        return cognito.set_ui_customization(UserPoolId=pool_id, ClientId=client_id, CSS=css)

    with ThreadPoolExecutor(max_workers=2) as pool:
        fut_a = pool.submit(_set, css_a)
        fut_b = pool.submit(_set, css_b)
        fut_a.result()
        fut_b.result()

    final = cognito.get_ui_customization(UserPoolId=pool_id, ClientId=client_id)["UICustomization"]
    assert final.get("CSS") in (css_a, css_b), (
        f"final CSS {final.get('CSS')!r} is neither racing value -- write was merged/corrupted"
    )

    # Stability: the settled value must not flap between the two candidates on repeated
    # independent reads -- a torn/eventually-consistent target could otherwise show the
    # correct value once and something else moments later.
    settled = final["CSS"]
    for _ in range(3):
        time.sleep(0.5)
        again = cognito.get_ui_customization(UserPoolId=pool_id, ClientId=client_id)["UICustomization"]
        assert again.get("CSS") == settled, (
            f"CSS changed on a read with no intervening write: {settled!r} -> {again.get('CSS')!r}"
        )


def _create_user_pool(ctx, cognito, **overrides):
    params = {
        "PoolName": ctx.unique_name("sim2real-behav-pool-"),
        "UserPoolTags": {"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"},
    }
    params.update(overrides)
    pool_id = cognito.create_user_pool(**params)["UserPool"]["Id"]
    ctx.on_cleanup(lambda: cognito.delete_user_pool(UserPoolId=pool_id))
    return pool_id


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last observed={last!r})")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
