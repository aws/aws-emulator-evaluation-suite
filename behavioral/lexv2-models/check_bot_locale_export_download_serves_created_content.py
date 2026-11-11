"""bot-locale-export-download-serves-created-content."""
from __future__ import annotations

import json
import time
import urllib.request
import zipfile
from io import BytesIO

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "bot-locale-export-download-serves-created-content"
GROUP = 'export-content'
SERVICES = ['lexv2-models']

_LOCALE = "en_US"
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


def _teardown(undo, *not_found: str):
    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _lex_role(ctx) -> str:
    """A role lexv2 can assume, created by this check and torn down with it."""
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-lexv2-")
    arn = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=json.dumps(_TRUST),
        Description=f"sim2real-{CHECK}",
    )["Role"]["Arn"]
    ctx.on_cleanup(_teardown(lambda: iam.delete_role(RoleName=name), "NoSuchEntity"))
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


@tags(
    "axis:happy-path",
    "cap:c1",
    "concern:representation",
    "concern:data-plane",
    "dp:endpoint",
    "plane:data",
)
def run(ctx) -> None:
    """A completed locale export's download URL serves a zip whose BotLocale.json and the
    created intent's Intent.json carry the exact fields the locale and intent were created with.

    Reference: https://docs.aws.amazon.com/lexv2/latest/dg/export.html
    """
    lex = ctx.client("lexv2-models")
    bot_id = _new_bot(ctx, lex)
    bot_name = lex.describe_bot(botId=bot_id)["botName"]

    lex.create_bot_locale(
        botId=bot_id, botVersion="DRAFT", localeId=_LOCALE, nluIntentConfidenceThreshold=0.40,
    )
    _wait(
        lambda: lex.describe_bot_locale(botId=bot_id, botVersion="DRAFT", localeId=_LOCALE)[
            "botLocaleStatus"
        ],
        lambda s: s != "Creating",
        180,
        "the locale to leave Creating",
    )
    lex.create_intent(
        botId=bot_id, botVersion="DRAFT", localeId=_LOCALE, intentName="OrderPizza",
        sampleUtterances=[{"utterance": "I want to order a pizza"}],
    )

    export_id = lex.create_export(
        resourceSpecification={
            "botLocaleExportSpecification": {
                "botId": bot_id, "botVersion": "DRAFT", "localeId": _LOCALE,
            }
        },
        fileFormat="LexJson",
    )["exportId"]
    ctx.on_cleanup(_teardown(
        lambda: lex.delete_export(exportId=export_id), "ResourceNotFoundException",
    ))
    export = _wait(
        lambda: lex.describe_export(exportId=export_id),
        lambda d: d["exportStatus"] in ("Completed", "Failed"),
        180,
        "the export to settle",
    )
    assert export["exportStatus"] == "Completed", (
        f"the export settled at {export['exportStatus']!r}, expected 'Completed'; "
        f"failureReasons={export.get('failureReasons')!r}"
    )

    url, headers = ctx.endpoint_route(export["downloadUrl"])
    req = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(req, timeout=30) as resp:
        payload = resp.read()
    assert payload[:4] == b"PK\x03\x04", (
        f"the download served {payload[:4]!r} first, not a zip local-file-header signature"
    )
    archive = zipfile.ZipFile(BytesIO(payload))

    locale_path = f"{bot_name}/BotLocales/{_LOCALE}/BotLocale.json"
    intent_path = f"{bot_name}/BotLocales/{_LOCALE}/Intents/OrderPizza/Intent.json"
    names = archive.namelist()
    assert locale_path in names, f"{locale_path!r} is missing from the export; entries={names!r}"
    assert intent_path in names, f"{intent_path!r} is missing from the export; entries={names!r}"

    locale_doc = json.loads(archive.read(locale_path))
    assert locale_doc["identifier"] == _LOCALE, (
        f"BotLocale.json identifier is {locale_doc['identifier']!r}, expected {_LOCALE!r}"
    )
    assert locale_doc["nluConfidenceThreshold"] == 0.40, (
        f"BotLocale.json nluConfidenceThreshold is {locale_doc['nluConfidenceThreshold']!r}, "
        "expected 0.4"
    )

    intent_doc = json.loads(archive.read(intent_path))
    assert intent_doc["name"] == "OrderPizza", (
        f"Intent.json name is {intent_doc['name']!r}, expected 'OrderPizza'"
    )
    utterances = [u["utterance"] for u in intent_doc["sampleUtterances"]]
    assert utterances == ["I want to order a pizza"], (
        f"Intent.json sampleUtterances are {utterances!r}, expected the one utterance created"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
