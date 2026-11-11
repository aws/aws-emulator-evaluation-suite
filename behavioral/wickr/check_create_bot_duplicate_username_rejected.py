"""create-bot-duplicate-username-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-bot-duplicate-username-rejected"
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


def _rejection(fn):
    """(Error.Code, reasons) a ``ClientError`` carries; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response.get("reasons")
    raise AssertionError(f"expected CreateBot to be rejected, but it succeeded: {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A second CreateBot reusing a network's already-taken username is rejected with the
    documented validation error, and the original bot it collides with is unaffected.
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
    first = wickr.create_bot(
        networkId=network_id,
        username=username,
        displayName=ctx.unique_name("sim2real-behav-wickr-bot-"),
        groupId=group_id,
        challenge=ctx.unique_name("Sim2RealBehav"),
    )
    bot_id = first["botId"]
    ctx.on_cleanup(_teardown(lambda: wickr.delete_bot(networkId=network_id, botId=bot_id)))

    code, reasons = _rejection(
        lambda: wickr.create_bot(
            networkId=network_id,
            username=username,
            displayName=ctx.unique_name("sim2real-behav-wickr-bot-dup-"),
            groupId=group_id,
            challenge=ctx.unique_name("Sim2RealBehavDup"),
        )
    )
    assert code == "ValidationError", f"expected ValidationError, got {code!r}"
    assert reasons == [{"field": "username", "reason": "username is unavailable"}], (
        f"unexpected validation reasons {reasons!r}"
    )

    # Positive control: the original bot the rejected call collided with is untouched, and no
    # second bot was created under the same username.
    listed = wickr.list_bots(networkId=network_id, username=username)["bots"]
    assert [b["botId"] for b in listed] == [bot_id], (
        f"ListBots for {username!r} returned {[b['botId'] for b in listed]!r}, expected only "
        f"the original bot {bot_id!r}"
    )
    got = wickr.get_bot(networkId=network_id, botId=bot_id)
    assert got["username"] == username, f"GetBot username {got['username']!r}, expected {username!r}"
    assert got["displayName"] == first["displayName"], (
        f"the rejected call must not have changed displayName: got {got['displayName']!r}, "
        f"expected {first['displayName']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
