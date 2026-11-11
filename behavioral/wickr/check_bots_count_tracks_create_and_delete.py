"""bots-count-tracks-create-and-delete."""

from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "bots-count-tracks-create-and-delete"
GROUP = "counts"
SERVICES = ["wickr"]


def _teardown(undo, *not_found: str):
    """A cleanup running ``undo()`` where a failed delete raises, except on ``not_found`` codes."""

    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


@tags("axis:happy-path", "cap:c2", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetBotsCount reflects every CreateBot and DeleteBot, not a cached or static value.

    Reference: https://docs.aws.amazon.com/wickr/latest/APIReference/API_GetBotsCount.html
    """
    wickr = ctx.client("wickr", region="us-east-1")
    network_name = ctx.unique_name("sim2real")[:20]

    network = wickr.create_network(networkName=network_name, accessLevel="STANDARD")
    network_id = network["networkId"]
    ctx.on_cleanup(_teardown(lambda: wickr.delete_network(networkId=network_id), "ForbiddenError"))
    group_id = wickr.list_security_groups(networkId=network_id)["securityGroups"][0]["id"]

    empty = wickr.get_bots_count(networkId=network_id)
    assert empty["total"] == 0, f"a fresh network's bot total was {empty['total']!r}, expected 0"
    assert empty["active"] == 0, (
        f"a fresh network's active bots was {empty['active']!r}, expected 0"
    )

    bot_ids = []
    for _ in range(3):
        username = ctx.unique_name("sim2real-probe-") + "-bot"
        bot = wickr.create_bot(
            networkId=network_id,
            username=username,
            displayName="Probe Bot",
            groupId=group_id,
            challenge="Sim2realProbe!2345",
        )
        bot_ids.append(bot["botId"])

    three = wickr.get_bots_count(networkId=network_id)
    assert three["total"] == 3, f"after creating 3 bots, total was {three['total']!r}, expected 3"
    assert three["pending"] == 3, (
        f"after creating 3 bots, pending was {three['pending']!r}, expected 3 (a bot starts "
        "pending until it first connects)"
    )

    wickr.delete_bot(networkId=network_id, botId=bot_ids[0])

    two = wickr.get_bots_count(networkId=network_id)
    assert two["total"] == 2, f"after deleting 1 of 3 bots, total was {two['total']!r}, expected 2"
    assert two["pending"] == 2, (
        f"after deleting 1 of 3 bots, pending was {two['pending']!r}, expected 2"
    )

    listed = {b["botId"] for b in wickr.list_bots(networkId=network_id)["bots"]}
    assert listed == set(bot_ids[1:]), (
        f"ListBots returned {sorted(listed)}, expected the 2 surviving bots {sorted(bot_ids[1:])}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
