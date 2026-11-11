"""put-session-rejects-an-intent-the-locale-does-not-define."""
from __future__ import annotations

import base64
import gzip
import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-session-rejects-an-intent-the-locale-does-not-define"
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


def _client_error(fn):
    """Call fn(); return the (code, message) of the ClientError it raised.

    An unexpected SUCCESS raises instead of returning a falsy sentinel: "the target accepted
    input real AWS rejects" is the strongest signal there is and must not read as a code
    mismatch.
    """
    try:
        fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), error.get("Message")
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

@tags("axis:rejection", "cap:c1", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """PutSession refuses to seed an intent the built locale does not define, and stores nothing.

    The refusal leaves no session for GetSession to find, and the identical call naming the real
    intent is accepted.
    """
    lr = ctx.client("lexv2-runtime")
    bot_id, alias_id = _bot(ctx)
    bad_session = ctx.unique_name("sim2real-lex-sess-")

    code, message = _client_error(lambda: lr.put_session(
        botId=bot_id, botAliasId=alias_id, localeId=_LOCALE, sessionId=bad_session,
        sessionState={"dialogAction": {"type": "ElicitSlot", "slotToElicit": _SLOT},
                      "intent": {"name": "NoSuchIntent", "state": "InProgress"}}))
    assert code == "ValidationException", (
        f"seeding an undefined intent returned {code!r}, expected 'ValidationException'"
    )
    assert message == "The intent is invalid.", f"got message={message!r}"

    absent, absent_message = _client_error(lambda: lr.get_session(botId=bot_id, botAliasId=alias_id,
                                                localeId=_LOCALE, sessionId=bad_session))
    assert absent == "ResourceNotFoundException", (
        f"after the refused PutSession, GetSession returned {absent!r}, expected "
        f"'ResourceNotFoundException' -- the rejected call must not have created a session"
    )
    assert absent_message == (
        f"The session for user {bad_session} doesn\u2019t exist or has expired."
    ), f"got message={absent_message!r}"

    # Positive control: the same call, with the intent the locale does define.
    good_session = ctx.unique_name("sim2real-lex-sess-")
    put = lr.put_session(
        botId=bot_id, botAliasId=alias_id, localeId=_LOCALE, sessionId=good_session,
        sessionState={"dialogAction": {"type": "ElicitSlot", "slotToElicit": _SLOT},
                      "intent": {"name": _INTENT, "state": "InProgress"}})
    assert put["sessionId"] == good_session, (
        f"PutSession echoed {put['sessionId']!r}, sent {good_session!r}"
    )
    seeded = _decode(put["sessionState"])
    assert seeded["intent"]["name"] == _INTENT, (
        f"the accepted seed holds intent {seeded['intent']['name']!r}, expected {_INTENT!r}"
    )
    got = lr.get_session(botId=bot_id, botAliasId=alias_id, localeId=_LOCALE,
                         sessionId=good_session)
    assert got["sessionState"]["dialogAction"]["slotToElicit"] == _SLOT, (
        f"the accepted seed reads back as {got['sessionState']['dialogAction']!r}, expected an "
        f"elicitation of {_SLOT!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
