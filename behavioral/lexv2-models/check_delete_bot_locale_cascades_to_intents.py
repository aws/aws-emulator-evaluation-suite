"""delete-bot-locale-cascades-to-intents."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-bot-locale-cascades-to-intents"
GROUP = 'locale-lifecycle'
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


def _client_error(fn):
    """Call fn(); return the (code, message) of the ClientError it raises.

    An unexpected SUCCESS raises rather than returning a falsy sentinel: an emulator that accepts
    input real AWS rejects is the strongest signal available, and a sentinel would read as a
    harmless naming mismatch.
    """
    try:
        fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError("the call was expected to fail but returned successfully")


@tags(
    "axis:happy-path",
    "cap:c1",
    "concern:representation",
    "concern:negative-classes",
    "plane:control",
)
def run(ctx) -> None:
    """After DeleteBotLocale, the locale and its intent and slot type read ResourceNotFoundException with the
    exact message, while a sibling locale keeps its intent and slot type and the bot stays Available.
    """
    lex = ctx.client("lexv2-models")
    bot_id = _new_bot(ctx, lex)

    def _add_locale(locale_id):
        lex.create_bot_locale(
            botId=bot_id, botVersion="DRAFT", localeId=locale_id,
            nluIntentConfidenceThreshold=_THRESHOLD,
        )
        _wait(
            lambda: lex.describe_bot_locale(
                botId=bot_id, botVersion="DRAFT", localeId=locale_id
            )["botLocaleStatus"],
            lambda s: s != "Creating",
            180,
            f"the {locale_id} locale to leave Creating",
        )
        slot_type_id = lex.create_slot_type(
            botId=bot_id, botVersion="DRAFT", localeId=locale_id, slotTypeName="PizzaSize",
            slotTypeValues=[{"sampleValue": {"value": "large"}}],
            valueSelectionSetting={"resolutionStrategy": "TopResolution"},
        )["slotTypeId"]
        intent_id = lex.create_intent(
            botId=bot_id, botVersion="DRAFT", localeId=locale_id, intentName="OrderPizza",
            sampleUtterances=[{"utterance": "I want to order a pizza"}],
        )["intentId"]
        return slot_type_id, intent_id

    doomed_slot_type, doomed_intent = _add_locale(_LOCALE)
    kept_slot_type, kept_intent = _add_locale("es_US")

    lex.delete_bot_locale(botId=bot_id, botVersion="DRAFT", localeId=_LOCALE)

    def _locale_code():
        try:
            return lex.describe_bot_locale(
                botId=bot_id, botVersion="DRAFT", localeId=_LOCALE
            )["botLocaleStatus"]
        except ClientError as exc:
            return exc.response.get("Error", {}).get("Code")

    gone = _wait(
        _locale_code,
        lambda s: s == "ResourceNotFoundException",
        300,
        "the deleted locale to stop answering",
    )
    assert gone == "ResourceNotFoundException", (
        f"the deleted locale still reports {gone!r}"
    )
    locale_code, locale_message = _client_error(
        lambda: lex.describe_bot_locale(botId=bot_id, botVersion="DRAFT", localeId=_LOCALE)
    )
    assert locale_code == "ResourceNotFoundException", f"got code={locale_code!r}"
    assert locale_message == "Failed to retrieve resource since it does not exist", (
        f"got message={locale_message!r}"
    )

    code, message = _client_error(
        lambda: lex.describe_intent(
            botId=bot_id, botVersion="DRAFT", localeId=_LOCALE, intentId=doomed_intent
        )
    )
    assert code == "ResourceNotFoundException", (
        f"the deleted locale's intent still answers with {code!r}, expected "
        "'ResourceNotFoundException' — the delete did not cascade"
    )
    assert message == "Failed to retrieve resource since it does not exist", (
        f"got message={message!r}"
    )
    code, message = _client_error(
        lambda: lex.describe_slot_type(
            botId=bot_id, botVersion="DRAFT", localeId=_LOCALE, slotTypeId=doomed_slot_type
        )
    )
    assert code == "ResourceNotFoundException", (
        f"the deleted locale's slot type still answers with {code!r}, expected "
        "'ResourceNotFoundException'"
    )
    assert message == "Failed to retrieve resource since it does not exist", (
        f"got message={message!r}"
    )

    # The blast radius stopped at the locale: the sibling locale and the bot are intact.
    sibling = lex.describe_bot_locale(botId=bot_id, botVersion="DRAFT", localeId="es_US")
    assert sibling["botLocaleStatus"] == "NotBuilt", (
        f"the sibling locale reports {sibling['botLocaleStatus']!r}, expected an untouched 'NotBuilt'"
    )
    kept = lex.describe_intent(
        botId=bot_id, botVersion="DRAFT", localeId="es_US", intentId=kept_intent
    )
    assert kept["intentName"] == "OrderPizza", (
        f"the sibling locale's intent reads {kept['intentName']!r}, expected 'OrderPizza'"
    )
    assert lex.describe_slot_type(
        botId=bot_id, botVersion="DRAFT", localeId="es_US", slotTypeId=kept_slot_type
    )["slotTypeName"] == "PizzaSize", "the sibling locale's slot type did not survive"
    assert lex.describe_bot(botId=bot_id)["botStatus"] == "Available", (
        "deleting a locale left the bot itself out of Available"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
