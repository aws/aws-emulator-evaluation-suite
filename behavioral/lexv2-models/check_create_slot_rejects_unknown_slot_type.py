"""create-slot-rejects-unknown-slot-type."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-slot-rejects-unknown-slot-type"
GROUP = 'slot-validation'
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


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateSlot with a slotTypeId absent from the locale raises PreconditionFailedException with its exact
    message and leaves no slot (ListSlots is empty); the same request with a real slot type creates PizzaSize.
    """
    lex = ctx.client("lexv2-models")
    bot_id = _new_bot(ctx, lex)
    _new_locale(lex, bot_id)

    slot_type_id = lex.create_slot_type(
        botId=bot_id, botVersion="DRAFT", localeId=_LOCALE, slotTypeName="PizzaSize",
        slotTypeValues=[{"sampleValue": {"value": "large"}, "synonyms": [{"value": "big"}]}],
        valueSelectionSetting={"resolutionStrategy": "TopResolution"},
    )["slotTypeId"]
    intent_id = lex.create_intent(
        botId=bot_id, botVersion="DRAFT", localeId=_LOCALE, intentName="OrderPizza",
        sampleUtterances=[{"utterance": "I want a {PizzaSize} pizza"}],
    )["intentId"]

    elicitation = {
        "slotConstraint": "Required",
        "promptSpecification": {
            "messageGroups": [
                {"message": {"plainTextMessage": {"value": "What size pizza would you like?"}}}
            ],
            "maxRetries": 2, "allowInterrupt": True,
        },
    }
    # A well-formed id (same shape as a real one) that names nothing in this locale.
    absent_slot_type = "ZZZZZZZZZZ"
    assert absent_slot_type != slot_type_id, "the unknown id collided with the real one"

    code, message = _error(
        lambda: lex.create_slot(
            botId=bot_id, botVersion="DRAFT", localeId=_LOCALE, intentId=intent_id,
            slotName="Doomed", slotTypeId=absent_slot_type, valueElicitationSetting=elicitation,
        )
    )
    assert code == "PreconditionFailedException", (
        f"CreateSlot against an unknown slot type returned {code!r}, expected "
        "'PreconditionFailedException'"
    )
    assert message == "Failed to retrieve parent resource since it does not exist", (
        f"CreateSlot message: {message!r}"
    )

    def _slot_names():
        names, token = [], None
        while True:
            page = lex.list_slots(
                botId=bot_id, botVersion="DRAFT", localeId=_LOCALE, intentId=intent_id,
                maxResults=100, **({"nextToken": token} if token else {}),
            )
            names += [s["slotName"] for s in page.get("slotSummaries", [])]
            token = page.get("nextToken")
            if not token:
                return names

    assert _slot_names() == [], (
        f"the refused CreateSlot left slots {_slot_names()!r} behind; the intent must still have none"
    )

    # Positive control: the same request, differing only in the slot type id, is accepted.
    slot_id = lex.create_slot(
        botId=bot_id, botVersion="DRAFT", localeId=_LOCALE, intentId=intent_id,
        slotName="PizzaSize", slotTypeId=slot_type_id, valueElicitationSetting=elicitation,
    )["slotId"]
    assert _slot_names() == ["PizzaSize"], (
        f"after the accepted CreateSlot the intent lists {_slot_names()!r}, expected ['PizzaSize']"
    )
    assert lex.describe_slot(
        botId=bot_id, botVersion="DRAFT", localeId=_LOCALE, intentId=intent_id, slotId=slot_id
    )["slotTypeId"] == slot_type_id, "the created slot does not point at the slot type it was given"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
