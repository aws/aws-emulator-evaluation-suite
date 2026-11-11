"""create-vocabulary-without-phrases-or-fileuri-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-vocabulary-without-phrases-or-fileuri-rejected"
GROUP = "overly-permissive"
SERVICES = ["transcribe"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateVocabulary with neither Phrases nor VocabularyFileUri is rejected with
    BadRequestException, no vocabulary is created (effect absent), and supplying
    Phrases for the SAME name afterwards succeeds (positive control)."""
    tx = ctx.client("transcribe")
    name = ctx.unique_name("sim2real-behav-vocab-empty-")

    code, message = _client_error(lambda: tx.create_vocabulary(VocabularyName=name, LanguageCode="en-US"))
    assert code == "BadRequestException", f"expected BadRequestException, got {code!r}"
    expected = "Either Phrases or VocabularyFileUri field should be provided."
    assert message == expected, f"expected missing-source message {expected!r}, got {message!r}"

    # effect absent: nothing was created under this name (empirically Transcribe
    # reports this as BadRequestException, not the modeled NotFoundException --
    # see API_GetVocabulary.html: BadRequestException "can occur when the entity
    # you're trying to delete doesn't exist")
    code_missing, message_missing = _client_error(lambda: tx.get_vocabulary(VocabularyName=name))
    assert code_missing == "BadRequestException", (
        f"expected the never-created vocabulary to read back as BadRequestException, "
        f"got {code_missing!r}"
    )
    expected_missing = (
        "The requested vocabulary couldn't be found. Check the vocabulary name and try your request again."
    )
    assert message_missing == expected_missing, f"expected not-found message {expected_missing!r}, got {message_missing!r}"

    # positive control: the same name succeeds once a valid source is supplied
    tx.create_vocabulary(
        VocabularyName=name,
        LanguageCode="en-US",
        Phrases=["Test"],
        Tags=[{"Key": "sim2real-env", "Value": "behavioral"}],
    )
    ctx.on_cleanup(lambda: _delete_vocabulary_ignore_missing(ctx, name))
    got_name = tx.get_vocabulary(VocabularyName=name)["VocabularyName"]
    assert got_name == name, f"expected the positive-control vocabulary {name!r}, got {got_name!r}"


def _client_error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises, because
    an emulator ACCEPTING input real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")


def _delete_vocabulary_ignore_missing(ctx, name: str) -> None:
    tx = ctx.client("transcribe")
    try:
        tx.delete_vocabulary(VocabularyName=name)
    except ClientError as e:
        if e.response["Error"]["Code"] not in ("NotFoundException", "BadRequestException"):
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
