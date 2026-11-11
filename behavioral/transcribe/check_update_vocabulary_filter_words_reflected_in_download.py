"""update-vocabulary-filter-words-reflected-in-download."""
from __future__ import annotations

import time
import urllib.request

from botocore.exceptions import ClientError

from behavioral_harness import tags


def _routed_request(ctx, url, data=None, headers=None, **kwargs):
    """A urllib Request that reaches ``url`` on the target, with ``ctx.endpoint_route``'s headers."""
    target, route = ctx.endpoint_route(url)
    return urllib.request.Request(target, data=data, headers={**(headers or {}), **route}, **kwargs)


CHECK = "update-vocabulary-filter-words-reflected-in-download"
GROUP = "data-plane"
SERVICES = ["transcribe"]


@tags("axis:happy-path", "cap:c1", "concern:data-plane", "concern:representation", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """UpdateVocabularyFilter actually mutates the backing content: after an update,
    the DownloadUri content reflects the NEW word list and no longer contains the old
    one."""
    tx = ctx.client("transcribe")
    name = ctx.unique_name("sim2real-behav-filter-update-")
    tx.create_vocabulary_filter(
        VocabularyFilterName=name,
        LanguageCode="en-US",
        Words=["alpha"],
        Tags=[{"Key": "sim2real-env", "Value": "behavioral"}],
    )
    ctx.on_cleanup(lambda: _delete_filter_ignore_missing(ctx, name))

    initial_uri = _poll_filter_download_uri(ctx, name)
    initial_content = _download(ctx, initial_uri).upper()
    assert "ALPHA" in initial_content, f"expected seed word ALPHA in initial download, got: {initial_content!r}"

    tx.update_vocabulary_filter(VocabularyFilterName=name, Words=["bravo"])

    updated_uri = _poll_filter_download_uri(ctx, name)
    updated_content = _download(ctx, updated_uri).upper()
    assert "BRAVO" in updated_content, f"expected updated word BRAVO in download after update, got: {updated_content!r}"
    assert "ALPHA" not in updated_content, "stale word list persisted after UpdateVocabularyFilter"


def _poll_filter_download_uri(ctx, name: str, timeout_s: float = 60.0, interval_s: float = 3.0) -> str:
    tx = ctx.client("transcribe")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = tx.get_vocabulary_filter(VocabularyFilterName=name)
        if resp.get("DownloadUri"):
            return resp["DownloadUri"]
        time.sleep(interval_s)
    raise AssertionError(f"vocabulary filter {name} never produced a DownloadUri within {timeout_s}s")


def _download(ctx, url: str) -> str:
    with urllib.request.urlopen(_routed_request(ctx, url), timeout=30) as resp:
        return resp.read().decode("utf-8", errors="replace")


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
