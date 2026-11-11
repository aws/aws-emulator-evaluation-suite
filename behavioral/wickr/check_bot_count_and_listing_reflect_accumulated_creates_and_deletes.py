"""bot-count-and-listing-reflect-accumulated-creates-and-deletes."""

from __future__ import annotations

from behavioral_harness import tags

CHECK = "bot-count-and-listing-reflect-accumulated-creates-and-deletes"
GROUP = "bots"
SERVICES = ["wickr"]

#: Wickr's admin API is offered in a few regions; us-east-1 is one of them
#: (AWS Wickr endpoints and quotas, AWS General Reference).
_REGION = "us-east-1"


@tags(
    "axis:happy-path",
    "cap:c2",
    "concern:representation",
    "plane:control",
)
def run(ctx) -> None:
    """GetBotsCount's total and ListBots' membership track every bot a network holds across
    three creates and two deletes, not just the most recent mutation.

    Reference: https://docs.aws.amazon.com/wickr/latest/adminguide/what-is-wickr.html
    """
    wickr = ctx.client("wickr", region=_REGION)

    network_name = ctx.unique_name("sim2real")
    network = wickr.create_network(networkName=network_name, accessLevel="STANDARD")
    network_id = network["networkId"]
    ctx.on_cleanup(lambda: wickr.delete_network(networkId=network_id))

    group_id = wickr.list_security_groups(networkId=network_id)["securityGroups"][0]["id"]

    bot_ids = []
    for _ in range(3):
        username = ctx.unique_name("sim2real")[:17] + "bot"
        bot = wickr.create_bot(
            networkId=network_id,
            username=username,
            groupId=group_id,
            challenge="Sim2Real-Ch4llenge!",
        )
        bot_ids.append(bot["botId"])

    count_after_create = wickr.get_bots_count(networkId=network_id)
    assert count_after_create["total"] == 3, (
        f"expected 3 bots after 3 creates, GetBotsCount reported {count_after_create!r}"
    )
    listed_after_create = {b["botId"] for b in wickr.list_bots(networkId=network_id)["bots"]}
    assert listed_after_create == set(bot_ids), (
        f"ListBots returned {sorted(listed_after_create)}, expected exactly {sorted(bot_ids)}"
    )

    wickr.delete_bot(networkId=network_id, botId=bot_ids[0])
    wickr.delete_bot(networkId=network_id, botId=bot_ids[1])

    count_after_delete = wickr.get_bots_count(networkId=network_id)
    assert count_after_delete["total"] == 1, (
        f"expected 1 bot after deleting 2 of 3, GetBotsCount reported {count_after_delete!r}"
    )
    listed_after_delete = {b["botId"] for b in wickr.list_bots(networkId=network_id)["bots"]}
    assert listed_after_delete == {bot_ids[2]}, (
        f"ListBots returned {sorted(listed_after_delete)}, expected only {bot_ids[2]!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
