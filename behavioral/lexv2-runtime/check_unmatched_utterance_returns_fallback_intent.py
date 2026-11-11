"""unmatched-utterance-returns-fallback-intent."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "unmatched-utterance-returns-fallback-intent"
GROUP = 'recognition'
SERVICES = ['lexv2-runtime']

# ===== shared helpers =====

_LOCALE = 'en_US'
_INTENT = 'OrderShake'
_SLOT = 'Flavor'
_SLOT_TYPE = 'Flavor'
_FLAVORS = ('chocolate', 'vanilla', 'strawberry')
_PROMPT = 'What flavor would you like?'
_CLOSING_TEXT = 'Your shake is on the way.'
_THRESHOLD = 0.40
_UTTERANCES = [{"utterance": "i would like a {Flavor} shake"},
               {"utterance": "order a shake"},
               {"utterance": "i would like a shake"}]
_CLOSING = {"closingResponse": {"messageGroups": [
    {"message": {"plainTextMessage": {"value": _CLOSING_TEXT}}}]}}


def _error_code(fn):
    """Call fn(); return the botocore Error.Code of the ClientError it raised.

    An unexpected SUCCESS raises instead of returning a falsy sentinel: "the target accepted
    input real AWS rejects" is the strongest signal there is and must not read as a code
    mismatch.
    """
    try:
        fn()
    except ClientError as exc:
        return exc.response.get("Error", {}).get("Code")
    raise AssertionError("the call unexpectedly succeeded; expected a ClientError")


def _teardown(fn, label):
    """Run a delete, retrying while it races the resource it depends on."""
    last = None
    for _ in range(10):
        try:
            fn()
            return
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code in ("ResourceNotFoundException", "NoSuchEntity"):
                return
            last = f"{code}: {exc.response.get('Error', {}).get('Message')}"
            time.sleep(6)
    raise RuntimeError(f"{label} was not deleted: {last}")


def _await(read, wanted, label, budget=180):
    """Poll read() until it returns a member of wanted; fail naming what it got stuck on."""
    deadline = time.time() + budget
    seen = None
    while time.time() < deadline:
        seen = read()
        if seen in wanted:
            return seen
        assert seen != "Failed", f"{label} reached terminal state {seen!r}"
        time.sleep(3)
    raise AssertionError(f"{label} stuck at {seen!r}, wanted one of {sorted(wanted)}")


def _lex_role(ctx):
    """An IAM role a Lex V2 bot can assume, torn down after the bot. Returns its ARN."""
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-lexv2-role-")
    trust = {"Version": "2012-10-17",
             "Statement": [{"Effect": "Allow",
                            "Principal": {"Service": "lexv2.amazonaws.com"},
                            "Action": "sts:AssumeRole"}]}
    arn = iam.create_role(RoleName=name, AssumeRolePolicyDocument=json.dumps(trust),
                          Description=f"sim2real lex-runtime-v2 check {CHECK}",
                          Tags=[{"Key": "sim2real", "Value": CHECK}])["Role"]["Arn"]
    ctx.on_cleanup(lambda: _teardown(lambda: iam.delete_role(RoleName=name),
                                     f"iam role {name}"))
    iam.put_role_policy(
        RoleName=name, PolicyName="lexv2-runtime",
        PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": [
            {"Effect": "Allow",
             "Action": ["polly:SynthesizeSpeech", "comprehend:DetectSentiment"],
             "Resource": "*"}]}))
    ctx.on_cleanup(lambda: _teardown(
        lambda: iam.delete_role_policy(RoleName=name, PolicyName="lexv2-runtime"),
        f"inline policy on iam role {name}"))
    # IAM propagation exposes no condition to poll: _bot() retries CreateBot until the role is
    # assumable.
    return arn


def _test_alias(ctx, bot_id):
    """The bot's own DRAFT test alias id, derived rather than assumed."""
    lm = ctx.client("lexv2-models")
    found, token = [], None
    while True:
        kw = {"botId": bot_id, "maxResults": 100}
        if token:
            kw["nextToken"] = token
        page = lm.list_bot_aliases(**kw)
        found.extend(a for a in page["botAliasSummaries"] if a.get("botVersion") == "DRAFT")
        token = page.get("nextToken")
        if not token:
            break
    assert len(found) == 1, f"expected exactly one DRAFT alias on {bot_id}, got {found!r}"
    return found[0]["botAliasId"]


def _bot(ctx, build=True):
    """Author the minimum en_US bot this suite needs. Returns (bot_id, alias_id).

    One intent with three sample utterances, one required slot over a three-value custom slot
    type, and a closing response -- the smallest model that can be recognized, elicited against
    and fulfilled.
    """
    lm = ctx.client("lexv2-models")
    role_arn = _lex_role(ctx)
    bot_name = ctx.unique_name("sim2real-lexv2-bot-")
    created = None
    left = ctx.time_left()
    deadline = time.time() + (70 if left is None else max(1.0, min(70, left - 5.0)))
    while time.time() < deadline:
        try:
            created = lm.create_bot(botName=bot_name, roleArn=role_arn,
                                    dataPrivacy={"childDirected": False},
                                    idleSessionTTLInSeconds=300,
                                    description=f"sim2real lex-runtime-v2 check {CHECK}",
                                    botTags={"sim2real": CHECK})
            break
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "ValidationException":
                raise
            time.sleep(2)  # the new role is not assumable yet
    assert created is not None, (
        f"CreateBot never accepted role {role_arn!r} within the retry budget"
    )
    bot_id = created["botId"]
    ctx.on_cleanup(lambda: _teardown(
        lambda: lm.delete_bot(botId=bot_id, skipResourceInUseCheck=True), f"lex bot {bot_id}"))
    _await(lambda: lm.describe_bot(botId=bot_id)["botStatus"], {"Available"},
           f"bot {bot_id}")

    lm.create_bot_locale(botId=bot_id, botVersion="DRAFT", localeId=_LOCALE,
                         nluIntentConfidenceThreshold=_THRESHOLD,
                         voiceSettings={"voiceId": "Joanna", "engine": "neural"})
    _await(lambda: lm.describe_bot_locale(botId=bot_id, botVersion="DRAFT",
                                          localeId=_LOCALE)["botLocaleStatus"],
           {"NotBuilt"}, f"locale {_LOCALE} on {bot_id}")
    slot_type = lm.create_slot_type(
        slotTypeName=_SLOT_TYPE, botId=bot_id, botVersion="DRAFT", localeId=_LOCALE,
        slotTypeValues=[{"sampleValue": {"value": v}} for v in _FLAVORS],
        valueSelectionSetting={"resolutionStrategy": "TopResolution"})
    intent = lm.create_intent(intentName=_INTENT, botId=bot_id, botVersion="DRAFT",
                              localeId=_LOCALE, sampleUtterances=_UTTERANCES,
                              intentClosingSetting=_CLOSING)
    slot = lm.create_slot(
        slotName=_SLOT, botId=bot_id, botVersion="DRAFT", localeId=_LOCALE,
        intentId=intent["intentId"], slotTypeId=slot_type["slotTypeId"],
        valueElicitationSetting={"slotConstraint": "Required", "promptSpecification": {
            "messageGroups": [{"message": {"plainTextMessage": {"value": _PROMPT}}}],
            "maxRetries": 2}})
    lm.update_intent(intentId=intent["intentId"], intentName=_INTENT, botId=bot_id,
                     botVersion="DRAFT", localeId=_LOCALE, sampleUtterances=_UTTERANCES,
                     slotPriorities=[{"priority": 1, "slotId": slot["slotId"]}],
                     intentClosingSetting=_CLOSING)
    if build:
        _build(ctx, bot_id)
    return bot_id, _test_alias(ctx, bot_id)


def _build(ctx, bot_id):
    """Build the DRAFT en_US locale and wait for it to be servable."""
    lm = ctx.client("lexv2-models")
    lm.build_bot_locale(botId=bot_id, botVersion="DRAFT", localeId=_LOCALE)
    _await(lambda: lm.describe_bot_locale(botId=bot_id, botVersion="DRAFT",
                                          localeId=_LOCALE)["botLocaleStatus"],
           {"Built"}, f"build of locale {_LOCALE} on {bot_id}", budget=300)

# ===== end shared helpers =====

@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """An utterance nothing scores above the locale's threshold lands on FallbackIntent.

    The bot's own intent scores under the locale's nluIntentConfidenceThreshold, FallbackIntent
    is selected with nothing filled, and the same bot still recognizes the matching utterance.
    """
    lr = ctx.client("lexv2-runtime")
    bot_id, alias_id = _bot(ctx)
    session = ctx.unique_name("sim2real-lex-sess-")

    r = lr.recognize_text(botId=bot_id, botAliasId=alias_id, localeId=_LOCALE,
                          sessionId=session,
                          text="what is the weather in reykjavik tomorrow afternoon")

    state = r["sessionState"]
    assert state["intent"]["name"] == "FallbackIntent", (
        f"an unmatched utterance selected {state['intent']['name']!r}, expected "
        f"'FallbackIntent'"
    )
    assert state["dialogAction"]["type"] == "Close", (
        f"the fallback left dialogAction {state['dialogAction']!r}, expected 'Close'"
    )
    assert state["intent"]["slots"] == {}, (
        f"the fallback intent carries slots {state['intent']['slots']!r}, expected none"
    )
    names = [i["intent"]["name"] for i in r["interpretations"]]
    assert names[0] == "FallbackIntent", (
        f"the top interpretation was {names[0]!r}, expected 'FallbackIntent'; "
        f"interpretations were {names!r}"
    )
    scored = [i for i in r["interpretations"] if "nluConfidence" in i]
    assert len(scored) == 1 and scored[0]["intent"]["name"] == _INTENT, (
        f"expected exactly one scored alternative, the bot's own {_INTENT!r}; got "
        f"{[(i['intent']['name'], i['nluConfidence']) for i in scored]!r}"
    )
    assert scored[0]["nluConfidence"]["score"] < _THRESHOLD, (
        f"{_INTENT!r} scored {scored[0]['nluConfidence']['score']!r} on an unrelated utterance, "
        f"at or above the locale's nluIntentConfidenceThreshold {_THRESHOLD!r} -- it would have "
        f"been selected instead of the fallback"
    )

    # Positive control: the same bot, in a fresh session, still recognizes its own utterance.
    ok = lr.recognize_text(botId=bot_id, botAliasId=alias_id, localeId=_LOCALE,
                           sessionId=session + "-control",
                           text="i would like a chocolate shake")
    assert ok["sessionState"]["intent"]["name"] == _INTENT, (
        f"the control utterance selected {ok['sessionState']['intent']['name']!r}, expected "
        f"{_INTENT!r} -- the fallback above was the bot failing, not the threshold working"
    )
    assert ok["interpretations"][0]["nluConfidence"]["score"] >= _THRESHOLD, (
        f"the control utterance scored "
        f"{ok['interpretations'][0]['nluConfidence']['score']!r}, below the threshold "
        f"{_THRESHOLD!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
