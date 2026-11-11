"""create-bot-weak-challenge-rejected-by-password-policy."""

from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-bot-weak-challenge-rejected-by-password-policy"
GROUP = "bots"
SERVICES = ["wickr"]

_WEAK_MESSAGE = (
    "password does not meet minimum requirements: \n"
    "      0 uppercase letter(s), \n"
    "      0 lowercase letter(s), \n"
    "      0 number(s), \n"
    "      0 symbol(s), \n"
    "      minimum 8 letters\n"
    "      "
)


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


@tags(
    "axis:rejection",
    "cap:c1",
    "concern:negative-classes",
    "concern:representation",
    "plane:control",
)
def run(ctx) -> None:
    """CreateBot enforces the default security group's 8-character minimum on the bot's
    challenge password, independent of the username-format check, and creates no bot.

    Reference: https://docs.aws.amazon.com/wickr/latest/adminguide/network-security-groups.html
    """
    wickr = ctx.client("wickr", region="us-east-1")
    network_name = ctx.unique_name("sim2real")[:20]

    network = wickr.create_network(networkName=network_name, accessLevel="STANDARD")
    network_id = network["networkId"]
    ctx.on_cleanup(_teardown(lambda: wickr.delete_network(networkId=network_id), "ForbiddenError"))
    group_id = wickr.list_security_groups(networkId=network_id)["securityGroups"][0]["id"]

    weak_username = ctx.unique_name("sim2real-probe-") + "-bot"
    try:
        result = wickr.create_bot(
            networkId=network_id,
            username=weak_username,
            displayName="Weak",
            groupId=group_id,
            challenge="short1",
        )
    except ClientError as exc:
        error = exc.response["Error"]
        reasons = exc.response.get("reasons", [])
    else:
        raise AssertionError(f"a 6-character challenge was accepted: {result!r}")

    assert error["Code"] == "ValidationError", f"expected ValidationError, got {error['Code']!r}"
    assert error.get("Message") == "", (
        f"expected the top-level Error.Message to be empty with the detail in reasons[], "
        f"got {error.get('Message')!r}"
    )
    assert len(reasons) == 1, f"expected exactly one validation reason, got {reasons!r}"
    assert reasons[0]["field"] == "passwordPolicy", (
        f"expected the rejection on field 'passwordPolicy', got {reasons[0]['field']!r}"
    )
    assert reasons[0]["reason"] == _WEAK_MESSAGE, (
        f"unexpected password-policy message: {reasons[0]['reason']!r}"
    )

    listed = wickr.list_bots(networkId=network_id)["bots"]
    assert listed == [], f"a bot was created despite the rejected challenge: {listed!r}"

    strong_username = ctx.unique_name("sim2real-probe-") + "-bot"
    strong = wickr.create_bot(
        networkId=network_id,
        username=strong_username,
        displayName="Strong",
        groupId=group_id,
        challenge="longenoughpassword1",
    )
    assert strong["username"] == strong_username, (
        f"the positive control bot has username {strong['username']!r}, expected {strong_username!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
