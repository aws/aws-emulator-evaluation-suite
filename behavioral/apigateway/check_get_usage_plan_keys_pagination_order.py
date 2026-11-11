"""get-usage-plan-keys-pagination-order."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-usage-plan-keys-pagination-order"
GROUP = "ordering"
SERVICES = ["apigateway"]

_COUNT = 5


def _retrying(fn, *, max_attempts: int = 8, base_delay: float = 2.0):
    """Call fn(), retrying with exponential backoff on TooManyRequestsException."""
    attempt = 0
    while True:
        try:
            return fn()
        except ClientError as e:
            code = e.response.get("Error", {}).get("Code")
            attempt += 1
            if code != "TooManyRequestsException" or attempt >= max_attempts:
                raise
            time.sleep(base_delay * attempt)


def _poll_until_all_visible(list_fn, expected_count: int, timeout_s: float = 60.0, interval_s: float = 3.0):
    """Poll list_fn() until the full (unpaginated) items list has caught up.

    CreateUsagePlanKey's effect on the GetUsagePlanKeys listing is not
    guaranteed to be immediately read-after-write consistent on real AWS;
    right after the creation loop, the list can transiently be missing the
    most recently associated key(s). Poll for the expected count before
    asserting on ordering, rather than asserting against a possibly-stale
    snapshot.
    """
    deadline = time.monotonic() + timeout_s
    items = list_fn()
    while len(items) < expected_count and time.monotonic() < deadline:
        time.sleep(interval_s)
        items = list_fn()
    if len(items) < expected_count:
        raise TimeoutError(
            f"GetUsagePlanKeys still reports {len(items)}/{expected_count} keys after "
            f"{timeout_s}s of polling: {[i.get('name') for i in items]}"
        )
    return items


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetUsagePlanKeys lists every associated key exactly once, and paging with a small limit
    reconstructs exactly the order of a single unpaginated call (no reorder, duplicate or drop);
    the order itself is undocumented, so it is not asserted."""
    apigw = ctx.client("apigateway")

    plan_id = _retrying(
        lambda: apigw.create_usage_plan(
            name=ctx.unique_name("sim2real-plan-"),
            tags={"sim2real": "get-usage-plan-keys-pagination-order"},
        )
    )["id"]
    ctx.on_cleanup(lambda: apigw.delete_usage_plan(usagePlanId=plan_id))

    expected_names = set()
    for i in range(_COUNT):
        name = ctx.unique_name(f"sim2real-key-{i}-")
        key_id = _retrying(
            lambda name=name: apigw.create_api_key(
                name=name,
                enabled=True,
                tags={"sim2real": "get-usage-plan-keys-pagination-order"},
            )
        )["id"]
        ctx.on_cleanup(lambda kid=key_id: apigw.delete_api_key(apiKey=kid))
        ctx.on_cleanup(
            lambda kid=key_id: apigw.delete_usage_plan_key(usagePlanId=plan_id, keyId=kid)
        )
        _retrying(
            lambda kid=key_id: apigw.create_usage_plan_key(usagePlanId=plan_id, keyId=kid, keyType="API_KEY")
        )
        expected_names.add(name)
        # Give each association a clearly distinct creation timestamp: the
        # ordering guarantee relies on strictly increasing creation times,
        # and back-to-back calls risk a tied sort key on real AWS.
        time.sleep(1.0)

    # Full unpaginated fetch.
    full_items = _poll_until_all_visible(
        lambda: _retrying(lambda: apigw.get_usage_plan_keys(usagePlanId=plan_id))["items"],
        expected_count=_COUNT,
    )
    full_names = [item["name"] for item in full_items]
    assert len(full_names) == _COUNT and set(full_names) == expected_names, (
        f"expected every key in {sorted(expected_names)} to be listed exactly once, got {full_names}"
    )

    # Paginated fetch (small page size) must reconstruct the same order as the full fetch.
    collected = []
    kwargs = {"usagePlanId": plan_id, "limit": 2}
    while True:
        resp = _retrying(lambda kwargs=kwargs: apigw.get_usage_plan_keys(**kwargs))
        collected.extend(item["name"] for item in resp["items"])
        token = resp.get("position")
        if not token:
            break
        kwargs["position"] = token
    assert collected == full_names, (
        f"paginated order {collected} != unpaginated order {full_names} "
        "(GetUsagePlanKeys pagination must reconstruct the same order as a full fetch, "
        "even though that order is not guaranteed to match insertion order)"
    )



if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

