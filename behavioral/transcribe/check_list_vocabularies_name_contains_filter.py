"""list-vocabularies-name-contains-filter."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-vocabularies-name-contains-filter"
GROUP = "read"
SERVICES = ["transcribe"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListVocabularies(NameContains=...) matches a substring of a real vocabulary name
    and excludes it when the substring doesn't match."""
    tx = ctx.client("transcribe")
    name = ctx.unique_name("sim2real-behav-vocab-namefilter-")
    tx.create_vocabulary(
        VocabularyName=name,
        LanguageCode="en-US",
        Phrases=["Falcon"],
        Tags=[{"Key": "sim2real-env", "Value": "behavioral"}],
    )
    ctx.on_cleanup(lambda: _delete_vocabulary_ignore_missing(ctx, name))
    _poll_vocabulary_state(ctx, name, timeout_s=300, interval_s=10)

    matching_fragment = name[-12:]
    found = _list_all_names(ctx, name_contains=matching_fragment)
    assert name in found, f"{name} missing from ListVocabularies(NameContains={matching_fragment!r}): {found}"

    non_matching_fragment = "definitely-not-a-real-fragment-zzz"
    found_none = _list_all_names(ctx, name_contains=non_matching_fragment)
    assert name not in found_none, f"{name} unexpectedly matched unrelated NameContains filter"


def _list_all_names(ctx, name_contains: str) -> set[str]:
    tx = ctx.client("transcribe")
    names: set[str] = set()
    token = None
    while True:
        kwargs = {"NameContains": name_contains, "MaxResults": 100}
        if token:
            kwargs["NextToken"] = token
        resp = tx.list_vocabularies(**kwargs)
        for v in resp.get("Vocabularies", []):
            names.add(v["VocabularyName"])
        token = resp.get("NextToken")
        if not token:
            return names


def _poll_vocabulary_state(ctx, name: str, timeout_s: float = 300.0, interval_s: float = 10.0) -> str:
    tx = ctx.client("transcribe")
    deadline = time.monotonic() + timeout_s
    state = None
    while time.monotonic() < deadline:
        state = tx.get_vocabulary(VocabularyName=name)["VocabularyState"]
        if state != "PENDING":
            return state
        time.sleep(interval_s)
    raise AssertionError(f"vocabulary {name} stayed PENDING for {timeout_s}s (last state={state})")


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
