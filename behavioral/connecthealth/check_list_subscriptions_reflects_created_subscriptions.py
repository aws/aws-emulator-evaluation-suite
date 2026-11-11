"""list-subscriptions-reflects-created-subscriptions."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-subscriptions-reflects-created-subscriptions"
GROUP = "state"
SERVICES = ["connecthealth"]


def _create_domain(ch, name, **extra):
    deadline = time.monotonic() + 300.0
    while True:
        try:
            return ch.create_domain(name=name, **extra)
        except ClientError as err:
            code = err.response["Error"]["Code"]
            msg = err.response["Error"].get("Message", "")
            if code not in ("ServiceQuotaExceededException", "ValidationException") or "maximum limit" not in msg:
                raise
            if time.monotonic() > deadline:
                raise
            time.sleep(5.0)


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListSubscriptions returns every Subscription created under a Domain with its current status."""
    ch = ctx.client("connecthealth")
    domain_id = _create_domain(
        ch, ctx.unique_name("sim2real-conh-dom-"), tags={"sim2real-owner": "behavioral"}
    )["domainId"]
    ctx.on_cleanup(lambda: ch.delete_domain(domainId=domain_id))

    sub_a = ch.create_subscription(domainId=domain_id)["subscriptionId"]
    sub_b = ch.create_subscription(domainId=domain_id)["subscriptionId"]
    ch.deactivate_subscription(domainId=domain_id, subscriptionId=sub_b)

    listed = ch.list_subscriptions(domainId=domain_id)["subscriptions"]
    by_id = {s["subscriptionId"]: s for s in listed}

    assert len(listed) == 2, f"expected 2 subscriptions listed, got {len(listed)}: {listed!r}"
    assert set(by_id.keys()) == {sub_a, sub_b}, (
        f"expected listed ids to be exactly the created subscriptions ({sub_a!r}, {sub_b!r}), "
        f"got {set(by_id.keys())!r}"
    )
    assert by_id[sub_a]["status"] == "ACTIVE", (
        f"expected sub_a ({sub_a!r}) status ACTIVE, got {by_id[sub_a]['status']!r}"
    )
    assert by_id[sub_b]["status"] == "INACTIVE", (
        f"expected sub_b ({sub_b!r}) status INACTIVE after deactivate, got {by_id[sub_b]['status']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
