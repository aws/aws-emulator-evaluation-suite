"""delete-network-cascades-to-bots-and-security-groups."""

from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-network-cascades-to-bots-and-security-groups"
GROUP = "network-lifecycle"
SERVICES = ["wickr"]

#: Wickr's admin API is offered in a few regions; us-east-1 is one of them
#: (AWS Wickr endpoints and quotas, AWS General Reference).
_REGION = "us-east-1"


def _error(fn) -> tuple[str, str]:
    """(Error.Code, Error.Message) of the ClientError ``fn`` raises; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message", "")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _poll_until_refused(fn, *, budget_s: float = 120.0, poll_s: float = 3.0) -> tuple[str, str]:
    """(Error.Code, Error.Message) once ``fn`` starts raising a ClientError, polled until it does."""
    deadline = time.monotonic() + budget_s
    while True:
        try:
            fn()
        except ClientError as exc:
            err = exc.response["Error"]
            return err["Code"], err.get("Message", "")
        if time.monotonic() > deadline:
            raise AssertionError(f"still answering after {budget_s}s of polling")
        time.sleep(poll_s)


@tags(
    "axis:rejection",
    "cap:c1",
    "concern:negative-classes",
    "concern:representation",
    "plane:control",
)
def run(ctx) -> None:
    """DeleteNetwork is asynchronous: GetNetwork keeps answering for a window, then is refused,
    and that refusal propagates to the deleted network's own bots and security groups — never to
    a sibling network's.

    Reference: https://docs.aws.amazon.com/wickr/latest/adminguide/what-is-wickr.html
    """
    wickr = ctx.client("wickr", region=_REGION)

    doomed_name = ctx.unique_name("sim2real")
    doomed = wickr.create_network(networkName=doomed_name, accessLevel="STANDARD")
    doomed_id = doomed["networkId"]
    ctx.on_cleanup(lambda: _delete_network_ignore_gone(wickr, doomed_id))

    doomed_group_id = wickr.list_security_groups(networkId=doomed_id)["securityGroups"][0]["id"]
    doomed_bot = wickr.create_bot(
        networkId=doomed_id,
        username=ctx.unique_name("sim2real")[:17] + "bot",
        displayName="doomed bot",
        groupId=doomed_group_id,
        challenge="Sim2Real-Ch4llenge!",
    )
    doomed_bot_id = doomed_bot["botId"]

    control_name = ctx.unique_name("sim2real")
    control = wickr.create_network(networkName=control_name, accessLevel="STANDARD")
    control_id = control["networkId"]
    ctx.on_cleanup(lambda: _delete_network_ignore_gone(wickr, control_id))

    control_group_id = wickr.list_security_groups(networkId=control_id)["securityGroups"][0]["id"]
    control_bot = wickr.create_bot(
        networkId=control_id,
        username=ctx.unique_name("sim2real")[:17] + "bot",
        displayName="control bot",
        groupId=control_group_id,
        challenge="Sim2Real-Ch4llenge!",
    )
    control_bot_id = control_bot["botId"]

    wickr.delete_network(networkId=doomed_id)

    network_code, network_msg = _poll_until_refused(lambda: wickr.get_network(networkId=doomed_id))
    assert (network_code, network_msg) == ("ForbiddenError", "Network not found"), (
        f"expected the deleted network's GetNetwork to end up ForbiddenError/'Network not found', "
        f"got {network_code!r}: {network_msg!r}"
    )

    bot_code, bot_msg = _error(lambda: wickr.get_bot(networkId=doomed_id, botId=doomed_bot_id))
    assert (bot_code, bot_msg) == ("404", "Bot not found"), (
        f"expected the deleted network's bot to be unreachable (404/'Bot not found'), "
        f"got {bot_code!r}: {bot_msg!r}"
    )

    group_code, group_msg = _error(
        lambda: wickr.get_security_group(networkId=doomed_id, groupId=doomed_group_id)
    )
    assert (group_code, group_msg) == ("401", "invalid security group request"), (
        f"expected the deleted network's security group to be refused (401/'invalid security "
        f"group request'), got {group_code!r}: {group_msg!r}"
    )

    control_net = wickr.get_network(networkId=control_id)
    assert control_net["networkId"] == control_id, (
        f"the sibling network should be unaffected, got {control_net['networkId']!r}"
    )
    control_got_bot = wickr.get_bot(networkId=control_id, botId=control_bot_id)
    assert control_got_bot["botId"] == control_bot_id, (
        f"the sibling network's bot should still be reachable, got {control_got_bot!r}"
    )


def _delete_network_ignore_gone(wickr, network_id: str) -> None:
    try:
        wickr.delete_network(networkId=network_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("ForbiddenError", "404", "401"):
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
