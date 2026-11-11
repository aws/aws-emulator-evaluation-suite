"""bot-version-snapshots-draft-intent."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "bot-version-snapshots-draft-intent"
GROUP = 'versioning'
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


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateBotVersion numbers the first version "1" and goes Versioning -> Available with its locale Built;
    after DRAFT's utterances change, version 1 keeps the original two, and reading the intent under the uncut
    version 2 raises ResourceNotFoundException with its exact message.
    """
    lex = ctx.client("lexv2-models")
    bot_id = _new_bot(ctx, lex)
    _new_locale(lex, bot_id)
    _, intent_id, slot_id = _pizza_intent(lex, bot_id)
    built = _build(lex, bot_id)
    assert built["botLocaleStatus"] == "Built", (
        f"the DRAFT locale settled at {built['botLocaleStatus']!r} with failureReasons "
        f"{built.get('failureReasons')!r}; a version can only be cut from a built locale"
    )

    cut = lex.create_bot_version(
        botId=bot_id, botVersionLocaleSpecification={_LOCALE: {"sourceBotVersion": "DRAFT"}}
    )
    version = cut["botVersion"]
    assert version == "1", f"the first version was numbered {version!r}, expected '1'"
    assert cut["botStatus"] == "Versioning", (
        f"CreateBotVersion returned botStatus {cut['botStatus']!r}, expected 'Versioning'"
    )

    # The version row is not readable the instant CreateBotVersion returns, so poll THROUGH
    # ResourceNotFoundException rather than treating the first read as the answer.
    def _version_status():
        try:
            return lex.describe_bot_version(botId=bot_id, botVersion=version)["botStatus"]
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "ResourceNotFoundException":
                return "ResourceNotFoundException"
            raise

    status = _wait(
        _version_status,
        lambda s: s not in ("ResourceNotFoundException", "Creating", "Versioning"),
        300,
        "version 1 to become readable and settle",
    )
    assert status == "Available", f"version 1 settled at {status!r}, expected 'Available'"

    version_locale = lex.describe_bot_locale(
        botId=bot_id, botVersion=version, localeId=_LOCALE
    )["botLocaleStatus"]
    assert version_locale == "Built", (
        f"version 1's locale reports {version_locale!r}, expected 'Built'"
    )

    versions, token = [], None
    while True:
        page = lex.list_bot_versions(
            botId=bot_id, maxResults=100, **({"nextToken": token} if token else {})
        )
        versions += [s["botVersion"] for s in page.get("botVersionSummaries", [])]
        token = page.get("nextToken")
        if not token:
            break
    assert version in versions, (
        f"ListBotVersions returned {sorted(versions)!r}, which does not include the version just cut"
    )

    # Move DRAFT on by one utterance. Nothing else changes.
    draft_utterances = [
        {"utterance": "I want to order a pizza"},
        {"utterance": "I want a {PizzaSize} pizza"},
        {"utterance": "gimme a {PizzaSize} pizza"},
    ]
    lex.update_intent(
        botId=bot_id, botVersion="DRAFT", localeId=_LOCALE, intentId=intent_id,
        intentName="OrderPizza", sampleUtterances=draft_utterances,
        slotPriorities=[{"priority": 1, "slotId": slot_id}],
    )

    in_draft = [
        u["utterance"]
        for u in lex.describe_intent(
            botId=bot_id, botVersion="DRAFT", localeId=_LOCALE, intentId=intent_id
        )["sampleUtterances"]
    ]
    assert in_draft == [u["utterance"] for u in draft_utterances], (
        f"DRAFT reports utterances {in_draft!r}, not the three just written"
    )

    in_version = [
        u["utterance"]
        for u in lex.describe_intent(
            botId=bot_id, botVersion=version, localeId=_LOCALE, intentId=intent_id
        )["sampleUtterances"]
    ]
    assert in_version == ["I want to order a pizza", "I want a {PizzaSize} pizza"], (
        f"version 1 reports utterances {in_version!r} — a numbered version must keep the two it "
        "was cut with, not follow DRAFT"
    )

    # A version is addressable for reads only: the write path will not even accept its number.
    code, message = _client_error(
        lambda: lex.describe_intent(
            botId=bot_id, botVersion="2", localeId=_LOCALE, intentId=intent_id
        )
    )
    assert code == "ResourceNotFoundException", (
        f"reading an intent under an uncut version 2 returned {code!r}, expected "
        "'ResourceNotFoundException'"
    )
    assert message == "Failed to retrieve resource since it does not exist", (
        f"got message={message!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
