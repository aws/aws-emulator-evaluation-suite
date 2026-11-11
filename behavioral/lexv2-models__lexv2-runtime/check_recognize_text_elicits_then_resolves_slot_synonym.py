"""recognize-text-elicits-then-resolves-slot-synonym."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "recognize-text-elicits-then-resolves-slot-synonym"
GROUP = 'runtime-dialog'
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


def _error(fn):
    """Call fn(); return the botocore Error.Code and Error.Message of the ClientError it raises.

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


@tags('axis:happy-path', 'cap:c3', 'concern:data-plane', 'concern:negative-classes', 'dp:api', 'plane:data')
def run(ctx) -> None:
    """An utterance naming the intent but no size elicits PizzaSize with its authored prompt; the next turn's
    synonym "big" resolves to "large" and closes the dialog; after DeleteSession, GetSession raises
    ResourceNotFoundException with its exact message.
    """
    lex = ctx.client("lexv2-models")
    rt = ctx.client("lexv2-runtime")
    bot_id, alias_id = _built_pizza_bot(ctx, lex)

    session_id = ctx.unique_name("sim2real-lex-session-")

    def _say(text):
        return rt.recognize_text(
            botId=bot_id, botAliasId=alias_id, localeId=_LOCALE, sessionId=session_id, text=text
        )

    first = _say("I want to order a pizza")
    state = first["sessionState"]
    assert state["dialogAction"]["type"] == "ElicitSlot", (
        f"the first turn returned dialog action {state['dialogAction']['type']!r}, expected "
        "'ElicitSlot' — the required slot is unfilled"
    )
    assert state["dialogAction"]["slotToElicit"] == "PizzaSize", (
        f"the runtime elicited {state['dialogAction']['slotToElicit']!r}, expected 'PizzaSize'"
    )
    assert state["intent"]["name"] == "OrderPizza", (
        f"the first turn matched {state['intent']['name']!r}, expected 'OrderPizza'"
    )
    assert state["intent"]["state"] == "InProgress", (
        f"the intent is in state {state['intent']['state']!r}, expected 'InProgress'"
    )
    assert _resolved(state, "PizzaSize") == [], (
        f"PizzaSize already holds {_resolved(state, 'PizzaSize')!r} on a turn that named no value"
    )
    prompts = [m["content"] for m in first.get("messages") or []]
    assert prompts == ["What size pizza would you like?"], (
        f"the elicitation returned messages {prompts!r}, expected the prompt authored on the slot"
    )

    second = _say("big")
    state = second["sessionState"]
    assert _resolved(state, "PizzaSize") == ["large"], (
        f"answering with the synonym 'big' resolved to {_resolved(state, 'PizzaSize')!r}, expected "
        "['large'] — TopResolution must map a synonym onto its canonical value"
    )
    value = state["intent"]["slots"]["PizzaSize"]["value"]
    assert value["originalValue"] == "big", (
        f"originalValue was {value['originalValue']!r}, expected the 'big' that was actually said"
    )
    assert value["interpretedValue"] == "large", (
        f"interpretedValue was {value['interpretedValue']!r}, expected the canonical 'large'"
    )
    assert state["intent"]["state"] == "ReadyForFulfillment", (
        f"the intent is in state {state['intent']['state']!r} after its slot was filled, expected "
        "'ReadyForFulfillment'"
    )
    assert state["dialogAction"]["type"] == "Close", (
        f"the dialog action was {state['dialogAction']['type']!r} after the slot was filled, "
        "expected 'Close'"
    )

    held = rt.get_session(
        botId=bot_id, botAliasId=alias_id, localeId=_LOCALE, sessionId=session_id
    )
    assert _resolved(held["sessionState"], "PizzaSize") == ["large"], (
        f"GetSession reports PizzaSize as {_resolved(held['sessionState'], 'PizzaSize')!r}, "
        "expected the ['large'] the second turn resolved"
    )

    rt.delete_session(
        botId=bot_id, botAliasId=alias_id, localeId=_LOCALE, sessionId=session_id
    )
    code, message = _error(
        lambda: rt.get_session(
            botId=bot_id, botAliasId=alias_id, localeId=_LOCALE, sessionId=session_id
        )
    )
    assert code == "ResourceNotFoundException", (
        f"reading a deleted session returned {code!r}, expected 'ResourceNotFoundException'"
    )
    # AWS's text carries a typographic apostrophe (U+2019).
    assert message == f"The session for user {session_id} doesn\u2019t exist or has expired.", (
        f"GetSession message: {message!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
