"""bot-locale-build-transitions-to-built."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "bot-locale-build-transitions-to-built"
GROUP = 'build-lifecycle'
SERVICES = ['lexv2-models']

_LOCALE = "en_US"
_THRESHOLD = 0.40
_TRUST = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {"Service": "lexv2.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }
    ],
}
_RUNTIME_POLICY = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": ["polly:SynthesizeSpeech", "comprehend:DetectSentiment"],
            "Resource": "*",
        }
    ],
}
# Statuses a build passes THROUGH. AWS reports ReadyExpressTesting for a freshly built locale
# of the DRAFT version and only settles on Built a few seconds later, so the terminal state is Built
# and ReadyExpressTesting is transitional here.
_BUILD_PENDING = ("Creating", "Building", "Processing", "ReadyExpressTesting")


def _wait(fn, done, timeout, what):
    """Poll fn() until done(value); return the last value. A poll on an observable condition,
    never a bare sleep standing in for the wait."""
    deadline = time.time() + timeout
    value = fn()
    while not done(value):
        assert time.time() < deadline, (
            f"timed out after {timeout}s waiting for {what}; last observation was {value!r}"
        )
        time.sleep(3)
        value = fn()
    return value


def _lex_role(ctx) -> str:
    """A role lexv2 can assume, created by this check and torn down with it."""
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-lexv2-")
    arn = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=json.dumps(_TRUST),
        Description=f"sim2real-{CHECK}",
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    iam.put_role_policy(
        RoleName=name, PolicyName="lexv2-runtime", PolicyDocument=json.dumps(_RUNTIME_POLICY)
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=name, PolicyName="lexv2-runtime"))
    return arn


def _delete_bot(lex, bot_id) -> None:
    """Delete the bot, waiting out the transitional states DeleteBot refuses from."""
    for _ in range(40):
        try:
            status = lex.describe_bot(botId=bot_id)["botStatus"]
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "ResourceNotFoundException":
                return
            raise
        if status not in ("Creating", "Updating", "Versioning", "Deleting"):
            break
        time.sleep(3)
    try:
        lex.delete_bot(botId=bot_id, skipResourceInUseCheck=True)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise


def _new_bot(ctx, lex) -> str:
    """CreateBot with a freshly minted role, then wait for it to leave Creating."""
    role_arn = _lex_role(ctx)
    bot_id = lex.create_bot(
        botName=ctx.unique_name("sim2real-lexv2-bot-"),
        roleArn=role_arn,
        dataPrivacy={"childDirected": False},
        idleSessionTTLInSeconds=300,
        botType="Bot",
        botTags={"sim2real": CHECK},
    )["botId"]
    ctx.on_cleanup(lambda: _delete_bot(lex, bot_id))
    status = _wait(
        lambda: lex.describe_bot(botId=bot_id)["botStatus"],
        lambda s: s != "Creating",
        180,
        "the bot to leave Creating",
    )
    assert status == "Available", f"bot settled at {status!r}, expected 'Available'"
    return bot_id


def _new_locale(lex, bot_id) -> dict:
    lex.create_bot_locale(
        botId=bot_id,
        botVersion="DRAFT",
        localeId=_LOCALE,
        nluIntentConfidenceThreshold=_THRESHOLD,
    )
    return _wait(
        lambda: lex.describe_bot_locale(botId=bot_id, botVersion="DRAFT", localeId=_LOCALE),
        lambda d: d["botLocaleStatus"] != "Creating",
        180,
        "the locale to leave Creating",
    )


def _pizza_intent(lex, bot_id) -> tuple[str, str, str]:
    """The minimum a locale needs to build: a custom slot type, an intent with utterances, and
    a required slot that has an elicitation prompt and a priority."""
    slot_type_id = lex.create_slot_type(
        botId=bot_id,
        botVersion="DRAFT",
        localeId=_LOCALE,
        slotTypeName="PizzaSize",
        slotTypeValues=[
            {"sampleValue": {"value": "large"}, "synonyms": [{"value": "big"}]},
            {"sampleValue": {"value": "small"}, "synonyms": [{"value": "little"}]},
        ],
        valueSelectionSetting={"resolutionStrategy": "TopResolution"},
    )["slotTypeId"]
    intent_id = lex.create_intent(
        botId=bot_id,
        botVersion="DRAFT",
        localeId=_LOCALE,
        intentName="OrderPizza",
        sampleUtterances=[
            {"utterance": "I want to order a pizza"},
            {"utterance": "I want a {PizzaSize} pizza"},
        ],
    )["intentId"]
    slot_id = lex.create_slot(
        botId=bot_id,
        botVersion="DRAFT",
        localeId=_LOCALE,
        intentId=intent_id,
        slotName="PizzaSize",
        slotTypeId=slot_type_id,
        valueElicitationSetting={
            "slotConstraint": "Required",
            "promptSpecification": {
                "messageGroups": [
                    {"message": {"plainTextMessage": {"value": "What size pizza would you like?"}}}
                ],
                "maxRetries": 2,
                "allowInterrupt": True,
            },
        },
    )["slotId"]
    lex.update_intent(
        botId=bot_id,
        botVersion="DRAFT",
        localeId=_LOCALE,
        intentId=intent_id,
        intentName="OrderPizza",
        sampleUtterances=[
            {"utterance": "I want to order a pizza"},
            {"utterance": "I want a {PizzaSize} pizza"},
        ],
        slotPriorities=[{"priority": 1, "slotId": slot_id}],
    )
    return slot_type_id, intent_id, slot_id


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A fresh locale reads NotBuilt with no lastBuildSubmittedDateTime, BuildBotLocale reports Building and
    the locale settles at Built with 2 intents and 1 slot type and that timestamp; a second build advances
    the timestamp and settles at Built again.
    """
    lex = ctx.client("lexv2-models")
    bot_id = _new_bot(ctx, lex)

    fresh = _new_locale(lex, bot_id)
    assert fresh["botLocaleStatus"] == "NotBuilt", (
        f"a locale with no build submitted reported {fresh['botLocaleStatus']!r}, expected 'NotBuilt'"
    )
    assert "lastBuildSubmittedDateTime" not in fresh, (
        "a never-built locale already carries lastBuildSubmittedDateTime "
        f"{fresh.get('lastBuildSubmittedDateTime')!r}"
    )

    _pizza_intent(lex, bot_id)

    accepted = lex.build_bot_locale(botId=bot_id, botVersion="DRAFT", localeId=_LOCALE)
    assert accepted["botLocaleStatus"] == "Building", (
        f"BuildBotLocale returned status {accepted['botLocaleStatus']!r}, expected 'Building'"
    )
    submitted = accepted["lastBuildSubmittedDateTime"]

    built = _wait(
        lambda: lex.describe_bot_locale(botId=bot_id, botVersion="DRAFT", localeId=_LOCALE),
        lambda d: d["botLocaleStatus"] not in _BUILD_PENDING,
        600,
        "the build to settle",
    )
    assert built["botLocaleStatus"] == "Built", (
        f"the build settled at {built['botLocaleStatus']!r} with failureReasons "
        f"{built.get('failureReasons')!r}, expected 'Built'"
    )
    assert not built.get("failureReasons"), (
        f"a successful build reported failureReasons {built['failureReasons']!r}"
    )
    assert built["lastBuildSubmittedDateTime"] == submitted, (
        f"DescribeBotLocale reports lastBuildSubmittedDateTime "
        f"{built['lastBuildSubmittedDateTime']!r}, not the {submitted!r} BuildBotLocale accepted"
    )
    # FallbackIntent is created by the service with the locale, so a locale carrying one custom
    # intent counts two.
    assert built["intentsCount"] == 2, (
        f"the built locale counts {built['intentsCount']!r} intents, expected 2 "
        "(OrderPizza plus the service's FallbackIntent)"
    )
    assert built["slotTypesCount"] == 1, (
        f"the built locale counts {built['slotTypesCount']!r} slot types, expected 1"
    )

    resubmitted = lex.build_bot_locale(botId=bot_id, botVersion="DRAFT", localeId=_LOCALE)
    assert resubmitted["lastBuildSubmittedDateTime"] > submitted, (
        f"a second build reported lastBuildSubmittedDateTime "
        f"{resubmitted['lastBuildSubmittedDateTime']!r}, which did not advance past {submitted!r}"
    )
    rebuilt = _wait(
        lambda: lex.describe_bot_locale(botId=bot_id, botVersion="DRAFT", localeId=_LOCALE),
        lambda d: d["botLocaleStatus"] not in _BUILD_PENDING,
        600,
        "the second build to settle",
    )
    assert rebuilt["botLocaleStatus"] == "Built", (
        f"the second build settled at {rebuilt['botLocaleStatus']!r} with failureReasons "
        f"{rebuilt.get('failureReasons')!r}, expected 'Built'"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
