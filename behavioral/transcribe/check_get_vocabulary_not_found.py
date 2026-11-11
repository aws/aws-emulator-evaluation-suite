"""get-vocabulary-not-found."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-vocabulary-not-found"
GROUP = "read"
SERVICES = ["transcribe"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetVocabulary on a name never created fails with BadRequestException, not the modeled NotFoundException,
    and its exact not-found message, while the vocabulary the check created reads back by name."""
    tx = ctx.client("transcribe")
    real_name = ctx.unique_name("sim2real-behav-vocab-")
    tx.create_vocabulary(
        VocabularyName=real_name,
        LanguageCode="en-US",
        Phrases=["Colorado"],
        Tags=[{"Key": "sim2real-env", "Value": "behavioral"}],
    )
    ctx.on_cleanup(lambda: _delete_vocabulary_ignore_missing(ctx, real_name))

    control = tx.get_vocabulary(VocabularyName=real_name)
    assert control["VocabularyName"] == real_name, (
        f"positive control: expected GetVocabulary to return {real_name!r}, "
        f"got {control.get('VocabularyName')!r}"
    )

    missing_name = real_name + "-absent"
    error = _error(lambda: tx.get_vocabulary(VocabularyName=missing_name))
    assert error["Code"] == "BadRequestException", (
        f"expected BadRequestException for GetVocabulary on a never-created "
        f"name, got {error['Code']!r}"
    )
    expected = "The requested vocabulary couldn't be found. Check the vocabulary name and try your request again."
    assert error.get("Message") == expected, (
        f"expected not-found message {expected!r}, got {error.get('Message')!r}"
    )


def _error(fn):
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises, because an emulator
    ACCEPTING a call real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(
        f"expected GetVocabulary on a never-created name to be rejected, but it "
        f"SUCCEEDED and returned {result!r}"
    )


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
