"""recognize-text-fills-slot-from-utterance."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "recognize-text-fills-slot-from-utterance"
GROUP = 'runtime-recognition'
SERVICES = ['lexv2-models', 'lexv2-runtime']

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


def _build(lex, bot_id) -> dict:
    """Submit the build and poll until the locale leaves every pending state."""
    accepted = lex.build_bot_locale(botId=bot_id, botVersion="DRAFT", localeId=_LOCALE)
    assert accepted["botLocaleStatus"] == "Building", (
        f"BuildBotLocale returned status {accepted['botLocaleStatus']!r}, expected 'Building'"
    )
    return _wait(
        lambda: lex.describe_bot_locale(botId=bot_id, botVersion="DRAFT", localeId=_LOCALE),
        lambda d: d["botLocaleStatus"] not in _BUILD_PENDING,
        600,
        "the build to settle",
    )


def _test_alias(lex, bot_id) -> str:
    """The alias the service creates alongside the bot, discovered rather than hardcoded.

    ListBotAliases is paginated even though it is scoped to one bot we just created, because the
    page size is the service's to choose.
    """
    summaries, token = [], None
    while True:
        page = lex.list_bot_aliases(botId=bot_id, maxResults=100, **({"nextToken": token} if token else {}))
        summaries += page.get("botAliasSummaries", [])
        token = page.get("nextToken")
        if not token:
            break
    assert len(summaries) == 1, (
        f"expected exactly the service-created alias for this bot, got {[s['botAliasName'] for s in summaries]!r}"
    )
    alias = summaries[0]
    assert alias["botVersion"] == "DRAFT", (
        f"the service-created alias points at version {alias['botVersion']!r}, expected 'DRAFT'"
    )
    return alias["botAliasId"]


def _built_pizza_bot(ctx, lex) -> tuple[str, str]:
    """A bot with one built en_US locale, and the alias through which it can be invoked."""
    bot_id = _new_bot(ctx, lex)
    _new_locale(lex, bot_id)
    _pizza_intent(lex, bot_id)
    built = _build(lex, bot_id)
    assert built["botLocaleStatus"] == "Built", (
        f"the locale settled at {built['botLocaleStatus']!r} with failureReasons "
        f"{built.get('failureReasons')!r}; the runtime leg needs a built locale"
    )
    return bot_id, _test_alias(lex, bot_id)


def _resolved(session_state, slot_name) -> list:
    """The slot's resolvedValues, treating an absent slot and an unresolved one alike: both mean
    the utterance did not resolve to a value the slot type declares."""
    slot = (session_state["intent"].get("slots") or {}).get(slot_name)
    return list(((slot or {}).get("value") or {}).get("resolvedValues") or [])


@tags('axis:happy-path', 'cap:c3', 'concern:data-plane', 'dp:api', 'plane:data')
def run(ctx) -> None:
    """RecognizeText on a built bot returns OrderPizza above the confidence threshold with PizzaSize resolved
    to "large", ReadyForFulfillment and a Close dialog action, and GetSession holds the same slot value.
    """
    lex = ctx.client("lexv2-models")
    rt = ctx.client("lexv2-runtime")
    bot_id, alias_id = _built_pizza_bot(ctx, lex)

    session_id = ctx.unique_name("sim2real-lex-session-")
    answer = rt.recognize_text(
        botId=bot_id, botAliasId=alias_id, localeId=_LOCALE, sessionId=session_id,
        text="I want a large pizza",
    )

    assert answer["sessionId"] == session_id, (
        f"the runtime answered for session {answer['sessionId']!r}, not {session_id!r}"
    )

    interpretations = answer["interpretations"]
    top = interpretations[0]
    assert top["intent"]["name"] == "OrderPizza", (
        f"the top interpretation was {top['intent']['name']!r}, expected the authored 'OrderPizza'; "
        f"all interpretations were {[i['intent']['name'] for i in interpretations]!r}"
    )
    score = top["nluConfidence"]["score"]
    assert score >= _THRESHOLD, (
        f"the top interpretation scored {score!r}, below the locale's own "
        f"nluIntentConfidenceThreshold {_THRESHOLD!r}"
    )

    state = answer["sessionState"]
    assert _resolved(state, "PizzaSize") == ["large"], (
        f"PizzaSize resolved to {_resolved(state, 'PizzaSize')!r}, expected ['large'] — the "
        "utterance named a value the slot type declares"
    )
    value = state["intent"]["slots"]["PizzaSize"]["value"]
    assert value["originalValue"] == "large", (
        f"originalValue was {value['originalValue']!r}, expected the span 'large' from the utterance"
    )
    assert value["interpretedValue"] == "large", (
        f"interpretedValue was {value['interpretedValue']!r}, expected 'large'"
    )
    assert state["intent"]["state"] == "ReadyForFulfillment", (
        f"the intent is in state {state['intent']['state']!r}, expected 'ReadyForFulfillment' "
        "once its only slot is filled"
    )
    assert state["dialogAction"]["type"] == "Close", (
        f"the dialog action was {state['dialogAction']['type']!r}, expected 'Close' — there is "
        "nothing left to elicit"
    )

    # The fill is state, not just a response field: the session holds it for the next turn.
    held = rt.get_session(
        botId=bot_id, botAliasId=alias_id, localeId=_LOCALE, sessionId=session_id
    )
    assert _resolved(held["sessionState"], "PizzaSize") == ["large"], (
        f"GetSession reports PizzaSize as {_resolved(held['sessionState'], 'PizzaSize')!r}, "
        "expected the ['large'] RecognizeText filled"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
