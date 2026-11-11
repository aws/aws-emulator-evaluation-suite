"""create-app-instance-bot-malformed-lex-arn-rejected."""
from __future__ import annotations

import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-app-instance-bot-malformed-lex-arn-rejected"
GROUP = "overly-permissive"
SERVICES = ["chime-sdk-identity"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateAppInstanceBot with a LexBotAliasArn that is not a Lex V2 bot-alias ARN fails with ValidationException
    and the exact pattern message and lists no bot, while a well-formed alias ARN naming no real bot is accepted
    and listed until deleted."""
    # chime-sdk-identity's control plane is only in us-east-1 and eu-central-1; pinned so the
    # check runs the same regardless of ctx.region.
    client = ctx.client("chime-sdk-identity", region="us-east-1")
    instance_arn = client.create_app_instance(
        Name=ctx.unique_name("sim2real-chime-ai-"), Metadata="", ClientRequestToken=uuid.uuid4().hex
    )["AppInstanceArn"]
    ctx.on_cleanup(lambda: client.delete_app_instance(AppInstanceArn=instance_arn))

    bots_before = client.list_app_instance_bots(AppInstanceArn=instance_arn)["AppInstanceBots"]
    assert bots_before == [], f"expected no bots before the run, got {bots_before}"

    # Positive control: without this, "rejects a malformed Lex ARN" is indistinguishable from
    # "rejects every CreateAppInstanceBot call". A well-formed ARN shape is accepted even though
    # it names no real Lex V2 bot/alias — CreateAppInstanceBot validates ARN shape, not Lex
    # existence, so this needs no real Lex resources.
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    valid_lex_arn = f"arn:aws:lex:us-east-1:{account_id}:bot-alias/TSTBOTID01/TSTALIAS01"
    bot_arn = client.create_app_instance_bot(
        AppInstanceArn=instance_arn,
        ClientRequestToken=uuid.uuid4().hex,
        Configuration={
            "Lex": {
                "LexBotAliasArn": valid_lex_arn,
                "LocaleId": "en_US",
                "RespondsTo": "STANDARD_MESSAGES",
            }
        },
    )["AppInstanceBotArn"]
    bots = client.list_app_instance_bots(AppInstanceArn=instance_arn)["AppInstanceBots"]
    assert any(b["AppInstanceBotArn"] == bot_arn for b in bots), (
        f"expected {bot_arn} in {bots}"
    )
    client.delete_app_instance_bot(AppInstanceBotArn=bot_arn)
    bots = client.list_app_instance_bots(AppInstanceArn=instance_arn)["AppInstanceBots"]
    assert bots == [], f"expected no bots after deleting the control bot, got {bots}"

    code, message = _error(
        lambda: client.create_app_instance_bot(
            AppInstanceArn=instance_arn,
            ClientRequestToken=uuid.uuid4().hex,
            Configuration={
                "Lex": {
                    "LexBotAliasArn": "not-a-valid-lex-bot-alias-arn",
                    "LocaleId": "en_US",
                    "RespondsTo": "STANDARD_MESSAGES",
                }
            },
        )
    )
    assert code == "ValidationException", f"expected ValidationException, got {code}"
    expected_message = (
        "1 validation error detected: Value 'not-a-valid-lex-bot-alias-arn' at "
        "'configuration.lex.lexBotAliasArn' failed to satisfy constraint: Member must satisfy "
        "regular expression pattern: "
        "arn:aws:lex:[a-z]{2}-[a-z]+-\\d{1}:\\d{12}:bot-alias/[A-Z0-9]{10}/[A-Z0-9]{10}"
    )
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # Effect absent: no bot got created under the AppInstance despite the failed call.
    bots_after = client.list_app_instance_bots(AppInstanceArn=instance_arn)["AppInstanceBots"]
    assert bots_after == [], f"expected no bots after the rejected call, got {bots_after}"

    # Positive control: the underlying AppInstance itself is very much describable.
    desc = client.describe_app_instance(AppInstanceArn=instance_arn)["AppInstance"]
    assert desc["AppInstanceArn"] == instance_arn, (
        f"expected {instance_arn}, got {desc['AppInstanceArn']}"
    )


def _error(fn):
    """Call fn() and return its error (code, message); raise if the call succeeds."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
