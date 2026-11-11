"""vocabulary-transitions-to-failed-on-unreachable-file."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "vocabulary-transitions-to-failed-on-unreachable-file"
GROUP = "overly-permissive"
SERVICES = ["transcribe"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateVocabulary with a VocabularyFileUri in a missing bucket fails at once with BadRequestException and the
    exact message, GetVocabulary on that name fails with the not-found message, and a vocabulary built from Phrases is
    created and read back."""
    tx = ctx.client("transcribe")
    name = ctx.unique_name("sim2real-behav-vocab-badfile-")
    # A syntactically valid s3:// URI pointing at a bucket that was never created.
    bogus_uri = f"s3://{ctx.unique_name('sim2real-nonexistent-bucket-')}/phrases.txt"

    code, message = _client_error(
        lambda: tx.create_vocabulary(VocabularyName=name, LanguageCode="en-US", VocabularyFileUri=bogus_uri)
    )
    assert code == "BadRequestException", f"expected BadRequestException for an unreachable file URI, got {code!r}"
    expected = (
        "The URI that you provided doesn't point to an S3 object. "
        "Make sure that the object exists and try your request again."
    )
    assert message == expected, f"expected unreachable-URI message {expected!r}, got {message!r}"

    # effect absent: no vocabulary was ever created under this name (AWS answers
    # BadRequestException, not the modeled NotFoundException)
    code_missing, message_missing = _client_error(lambda: tx.get_vocabulary(VocabularyName=name))
    assert code_missing == "BadRequestException", (
        f"expected GetVocabulary on the never-created name to also report BadRequestException, got {code_missing!r}"
    )
    expected_missing = (
        "The requested vocabulary couldn't be found. Check the vocabulary name and try your request again."
    )
    assert message_missing == expected_missing, f"expected not-found message {expected_missing!r}, got {message_missing!r}"

    # positive control: a genuinely reachable request for the same operation still succeeds,
    # so the rejection above is specific to the unreachable file, not every CreateVocabulary call.
    other = ctx.unique_name("sim2real-behav-vocab-badfile-ok-")
    tx.create_vocabulary(VocabularyName=other, LanguageCode="en-US", Phrases=["Coruscant"],
                          Tags=[{"Key": "sim2real-env", "Value": "behavioral"}])
    ctx.on_cleanup(lambda: _delete_vocabulary_ignore_missing(ctx, other))
    got_name = tx.get_vocabulary(VocabularyName=other)["VocabularyName"]
    assert got_name == other, f"expected positive-control vocabulary {other!r} to exist, got name {got_name!r}"


def _client_error(fn):
    """Call fn(); return its error (code, message). An unexpected SUCCESS raises, because an
    emulator ACCEPTING a call real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")


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
