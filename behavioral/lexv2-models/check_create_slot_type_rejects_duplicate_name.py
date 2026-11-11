"""create-slot-type-rejects-duplicate-name."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-slot-type-rejects-duplicate-name"
GROUP = 'slot-type-validation'
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


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateSlotType with a name already taken in the locale raises ValidationException with its exact message
    and leaves the first slot type's values and resolution strategy unchanged; a different name is accepted.
    """
    lex = ctx.client("lexv2-models")
    bot_id = _new_bot(ctx, lex)
    _new_locale(lex, bot_id)

    first = lex.create_slot_type(
        botId=bot_id, botVersion="DRAFT", localeId=_LOCALE, slotTypeName="PizzaSize",
        slotTypeValues=[
            {"sampleValue": {"value": "large"}, "synonyms": [{"value": "big"}]},
            {"sampleValue": {"value": "small"}},
        ],
        valueSelectionSetting={"resolutionStrategy": "TopResolution"},
    )
    first_id = first["slotTypeId"]

    code, message = _client_error(
        lambda: lex.create_slot_type(
            botId=bot_id, botVersion="DRAFT", localeId=_LOCALE, slotTypeName="PizzaSize",
            slotTypeValues=[{"sampleValue": {"value": "gigantic"}}],
            valueSelectionSetting={"resolutionStrategy": "OriginalValue"},
        )
    )
    assert code == "ValidationException", (
        f"a duplicate slot type name returned {code!r}, expected 'ValidationException'"
    )
    assert message == (
        "Slot Type with name PizzaSize already exists. Use another name."
    ), f"got message={message!r}"

    # The refused call changed nothing: same id, same values, same resolution strategy.
    kept = lex.describe_slot_type(
        botId=bot_id, botVersion="DRAFT", localeId=_LOCALE, slotTypeId=first_id
    )
    assert [v["sampleValue"]["value"] for v in kept["slotTypeValues"]] == ["large", "small"], (
        f"the refused duplicate changed the slot type's values to "
        f"{[v['sampleValue']['value'] for v in kept['slotTypeValues']]!r}"
    )
    assert kept["valueSelectionSetting"]["resolutionStrategy"] == "TopResolution", (
        f"the refused duplicate changed the resolution strategy to "
        f"{kept['valueSelectionSetting']['resolutionStrategy']!r}"
    )

    def _named(name):
        """Slot type ids in THIS bot's locale carrying `name`. Scoped to a bot this check created,
        so the count is a property of the query, not of the account."""
        found, token = [], None
        while True:
            page = lex.list_slot_types(
                botId=bot_id, botVersion="DRAFT", localeId=_LOCALE, maxResults=100,
                **({"nextToken": token} if token else {}),
            )
            found += [
                s["slotTypeId"] for s in page.get("slotTypeSummaries", [])
                if s["slotTypeName"] == name
            ]
            token = page.get("nextToken")
            if not token:
                return found

    assert _named("PizzaSize") == [first_id], (
        f"the locale holds {_named('PizzaSize')!r} slot types named PizzaSize, expected only "
        f"{first_id!r}"
    )

    # Positive control: the name is what was taken, not the request shape.
    second_id = lex.create_slot_type(
        botId=bot_id, botVersion="DRAFT", localeId=_LOCALE, slotTypeName="DrinkSize",
        slotTypeValues=[{"sampleValue": {"value": "gigantic"}}],
        valueSelectionSetting={"resolutionStrategy": "OriginalValue"},
    )["slotTypeId"]
    assert _named("DrinkSize") == [second_id], (
        f"the accepted CreateSlotType is not listed: DrinkSize resolved to {_named('DrinkSize')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
