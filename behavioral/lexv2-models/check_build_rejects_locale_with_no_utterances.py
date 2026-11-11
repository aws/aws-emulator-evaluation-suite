"""build-rejects-locale-with-no-utterances."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "build-rejects-locale-with-no-utterances"
GROUP = 'build-rejected'
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


# The exact reason real AWS attributes the failure to.
_NO_UTTERANCE_REASON = (
    "The locale 'en_US' doesn't have any utterances. A locale must have at least one custom "
    "intent with a valid utterance. Add a custom intent and try your request again."
)


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Building a locale whose only custom intent has no sample utterances settles at Failed with exactly the
    no-utterance failure reason; after utterances are added the same locale builds to Built.
    """
    lex = ctx.client("lexv2-models")
    bot_id = _new_bot(ctx, lex)
    _new_locale(lex, bot_id)

    # Everything a build needs EXCEPT an utterance: the slot type exists, the intent exists.
    lex.create_slot_type(
        botId=bot_id, botVersion="DRAFT", localeId=_LOCALE, slotTypeName="PizzaSize",
        slotTypeValues=[{"sampleValue": {"value": "large"}, "synonyms": [{"value": "big"}]}],
        valueSelectionSetting={"resolutionStrategy": "TopResolution"},
    )
    intent_id = lex.create_intent(
        botId=bot_id, botVersion="DRAFT", localeId=_LOCALE, intentName="OrderPizza",
    )["intentId"]
    described = lex.describe_intent(
        botId=bot_id, botVersion="DRAFT", localeId=_LOCALE, intentId=intent_id
    )
    assert not described.get("sampleUtterances"), (
        f"the intent was created with utterances {described['sampleUtterances']!r}; this check "
        "needs one with none"
    )

    failed = _build(lex, bot_id)
    assert failed["botLocaleStatus"] == "Failed", (
        f"a build with no utterances settled at {failed['botLocaleStatus']!r}, expected 'Failed'"
    )
    assert failed.get("failureReasons") == [_NO_UTTERANCE_REASON], (
        f"the failed build reported failureReasons {failed.get('failureReasons')!r}, expected "
        f"exactly [{_NO_UTTERANCE_REASON!r}]"
    )
    # The effect is absent: the build ran (it has a submission time) and produced nothing built.
    assert "lastBuildSubmittedDateTime" in failed, (
        "the failed build left no lastBuildSubmittedDateTime, so it never ran at all"
    )

    # Positive control: supply the one missing input and the same locale builds.
    lex.update_intent(
        botId=bot_id, botVersion="DRAFT", localeId=_LOCALE, intentId=intent_id,
        intentName="OrderPizza",
        sampleUtterances=[{"utterance": "I want to order a pizza"}],
    )
    built = _build(lex, bot_id)
    assert built["botLocaleStatus"] == "Built", (
        f"after adding an utterance the build settled at {built['botLocaleStatus']!r} with "
        f"failureReasons {built.get('failureReasons')!r}, expected 'Built'"
    )
    assert not built.get("failureReasons"), (
        f"the successful build still reported failureReasons {built['failureReasons']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
