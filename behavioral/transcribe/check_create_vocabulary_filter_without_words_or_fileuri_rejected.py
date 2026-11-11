"""create-vocabulary-filter-without-words-or-fileuri-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-vocabulary-filter-without-words-or-fileuri-rejected"
GROUP = "overly-permissive"
SERVICES = ["transcribe"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateVocabularyFilter with neither Words nor VocabularyFilterFileUri is
    rejected with BadRequestException, no filter is created (effect absent), and
    supplying Words for the SAME name afterwards succeeds (positive control)."""
    tx = ctx.client("transcribe")
    name = ctx.unique_name("sim2real-behav-filter-empty-")

    code, message = _client_error(lambda: tx.create_vocabulary_filter(VocabularyFilterName=name, LanguageCode="en-US"))
    assert code == "BadRequestException", f"expected BadRequestException creating filter without Words/FileUri, got {code!r}"
    expected = (
        "You need to provide either the Words field or the VocabularyFilterFileUri field. "
        "Provide one of the fields and try your request again."
    )
    assert message == expected, f"expected missing-source message {expected!r}, got {message!r}"

    # effect absent: nothing was created under this name (empirically Transcribe
    # reports this as BadRequestException, not the modeled NotFoundException --
    # see API_GetVocabularyFilter.html: BadRequestException "can occur when the
    # entity you're trying to delete doesn't exist")
    code_missing, message_missing = _client_error(lambda: tx.get_vocabulary_filter(VocabularyFilterName=name))
    assert code_missing == "BadRequestException", f"expected BadRequestException getting a filter that was never created, got {code_missing!r}"
    expected_missing = (
        "The requested vocabulary filter couldn't be found. "
        "Check the vocabulary filter name and try your request again."
    )
    assert message_missing == expected_missing, f"expected not-found message {expected_missing!r}, got {message_missing!r}"

    # positive control: the same name succeeds once Words is supplied
    tx.create_vocabulary_filter(VocabularyFilterName=name, LanguageCode="en-US", Words=["darn"])
    ctx.on_cleanup(lambda: _delete_filter_ignore_missing(ctx, name))
    got_name = tx.get_vocabulary_filter(VocabularyFilterName=name)["VocabularyFilterName"]
    assert got_name == name, f"expected positive-control filter {name!r} to be gettable by that name, got {got_name!r}"


def _client_error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises, because
    an over-permissive target ACCEPTING input real AWS rejects is the strongest signal available."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _delete_filter_ignore_missing(ctx, name: str) -> None:
    tx = ctx.client("transcribe")
    try:
        tx.delete_vocabulary_filter(VocabularyFilterName=name)
    except ClientError as e:
        if e.response["Error"]["Code"] not in ("NotFoundException", "BadRequestException"):
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
