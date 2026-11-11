"""create-bot-appears-in-get-and-list."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-bot-appears-in-get-and-list"
GROUP = "bots"
SERVICES = ["wickr"]


def _teardown(undo, *not_found: str):
    """A cleanup running ``undo()`` where a failed delete raises."""

    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A bot created in a network's security group shows up in GetBot and in a
    ListBots lookup scoped to its own username, carrying the identity it was created with.
    """
    # Wickr is a region-pinned service, offered only in us-east-1.
    wickr = ctx.client("wickr", region="us-east-1")

    network_name = ctx.unique_name("sim2realbehavnet")[:20]
    net = wickr.create_network(networkName=network_name, accessLevel="STANDARD")
    network_id = net["networkId"]
    ctx.on_cleanup(_teardown(lambda: wickr.delete_network(networkId=network_id)))

    group_name = ctx.unique_name("sim2real-behav-wickr-sg-")
    group = wickr.create_security_group(
        networkId=network_id, name=group_name, securityGroupSettings={}
    )
    group_id = group["securityGroup"]["id"]
    ctx.on_cleanup(
        _teardown(lambda: wickr.delete_security_group(networkId=network_id, groupId=group_id))
    )

    username = ctx.unique_name("sim2realbehavwickr") + "bot"
    display_name = ctx.unique_name("sim2real-behav-wickr-bot-")
    created = wickr.create_bot(
        networkId=network_id,
        username=username,
        displayName=display_name,
        groupId=group_id,
        challenge=ctx.unique_name("Sim2RealBehav"),
    )
    bot_id = created["botId"]
    ctx.on_cleanup(_teardown(lambda: wickr.delete_bot(networkId=network_id, botId=bot_id)))
    assert created["username"] == username, f"expected username {username!r}, got {created['username']!r}"
    assert created["groupId"] == group_id, f"expected groupId {group_id!r}, got {created['groupId']!r}"

    got = wickr.get_bot(networkId=network_id, botId=bot_id)
    assert got["username"] == username, f"GetBot username {got['username']!r}, expected {username!r}"
    assert got["displayName"] == display_name, (
        f"GetBot displayName {got['displayName']!r}, expected {display_name!r}"
    )
    assert got["groupId"] == group_id, f"GetBot groupId {got['groupId']!r}, expected {group_id!r}"
    assert got["status"] == 1, f"a freshly created bot should be PENDING (1), got {got['status']!r}"
    assert got["hasChallenge"] is True, f"expected hasChallenge True, got {got['hasChallenge']!r}"
    assert got["suspended"] is False, f"expected suspended False, got {got['suspended']!r}"

    listed = wickr.list_bots(networkId=network_id, username=username)["bots"]
    assert [b["botId"] for b in listed] == [bot_id], (
        f"ListBots scoped to {username!r} returned bot ids {[b['botId'] for b in listed]!r}, "
        f"expected only {bot_id!r}"
    )
    assert listed[0]["groupId"] == group_id, (
        f"ListBots groupId {listed[0]['groupId']!r}, expected {group_id!r}"
    )
    assert listed[0]["status"] == 1, f"ListBots status {listed[0]['status']!r}, expected 1 (PENDING)"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
