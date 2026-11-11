"""put-session-seeds-dialog-state-for-the-next-turn."""
from __future__ import annotations

import base64
import gzip
import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-session-seeds-dialog-state-for-the-next-turn"
GROUP = 'sessions'
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


def _decode(header):
    """A RecognizeUtterance/PutSession response header: gzip, then base64. Returns the JSON."""
    assert isinstance(header, str) and header, f"header is {header!r}, expected a non-empty str"
    raw = base64.b64decode(header)
    assert raw[:2] == b"\x1f\x8b", (
        f"header payload does not start with the gzip magic: {raw[:8]!r}"
    )
    return json.loads(gzip.decompress(raw).decode("utf-8"))

@tags("axis:happy-path", "cap:c3", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """PutSession writes dialog state that the next RecognizeText turn actually continues.

    GetSession reads back the seeded elicitation, its slot prompt is re-issued, and the next turn
    fulfils the seeded intent carrying the seeded attributes and PutSession's request id.
    """
    lr = ctx.client("lexv2-runtime")
    bot_id, alias_id = _bot(ctx)
    session = ctx.unique_name("sim2real-lex-sess-")

    put = lr.put_session(
        botId=bot_id, botAliasId=alias_id, localeId=_LOCALE, sessionId=session,
        sessionState={"dialogAction": {"type": "ElicitSlot", "slotToElicit": _SLOT},
                      "intent": {"name": _INTENT, "state": "InProgress"},
                      "sessionAttributes": {"seededBy": "put-session"}})
    assert put["sessionId"] == session, f"PutSession echoed {put['sessionId']!r}, sent {session!r}"
    seeded = _decode(put["sessionState"])
    assert seeded["dialogAction"] == {"type": "ElicitSlot", "slotToElicit": _SLOT}, (
        f"PutSession returned dialogAction {seeded['dialogAction']!r}, expected the one sent"
    )
    assert [m["content"] for m in _decode(put["messages"])] == [_PROMPT], (
        f"PutSession returned messages {_decode(put['messages'])!r}, expected the slot's own "
        f"prompt {_PROMPT!r} for the elicitation it was told to enter"
    )
    origin = seeded["originatingRequestId"]

    got = lr.get_session(botId=bot_id, botAliasId=alias_id, localeId=_LOCALE,
                         sessionId=session)
    assert got["sessionState"]["intent"]["name"] == _INTENT, (
        f"GetSession reports intent {got['sessionState']['intent']['name']!r}, expected the "
        f"seeded {_INTENT!r}"
    )
    assert got["sessionState"]["intent"]["state"] == "InProgress", (
        f"GetSession reports intent state {got['sessionState']['intent']['state']!r}, expected "
        f"the seeded 'InProgress'"
    )
    assert got["sessionState"]["sessionAttributes"] == {"seededBy": "put-session"}, (
        f"GetSession reports attributes {got['sessionState']['sessionAttributes']!r}, expected "
        f"the seeded ones"
    )

    turn = lr.recognize_text(botId=bot_id, botAliasId=alias_id, localeId=_LOCALE,
                             sessionId=session, text="chocolate")
    state = turn["sessionState"]
    assert state["intent"]["state"] == "Fulfilled", (
        f"the turn after the seed left the intent {state['intent']['state']!r}, expected "
        f"'Fulfilled'"
    )
    assert state["intent"]["slots"][_SLOT]["value"]["interpretedValue"] == "chocolate", (
        f"slot {_SLOT!r} holds {state['intent']['slots'][_SLOT]!r} after the answering turn"
    )
    assert state["sessionAttributes"] == {"seededBy": "put-session"}, (
        f"the turn reports attributes {state['sessionAttributes']!r}; it must have continued "
        f"the session PutSession wrote, not started a fresh one"
    )
    assert state["originatingRequestId"] == origin, (
        f"the turn reports originatingRequestId {state['originatingRequestId']!r}, PutSession "
        f"minted {origin!r} -- the conversation must be the seeded one"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
