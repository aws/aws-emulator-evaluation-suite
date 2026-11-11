"""vocabulary-filter-content-roundtrip-via-download-uri."""
from __future__ import annotations

import time
import urllib.request

from botocore.exceptions import ClientError

from behavioral_harness import tags


def _routed_request(ctx, url, data=None, headers=None, **kwargs):
    """A urllib Request that reaches ``url`` on the target, with ``ctx.endpoint_route``'s headers."""
    target, route = ctx.endpoint_route(url)
    return urllib.request.Request(target, data=data, headers={**(headers or {}), **route}, **kwargs)


CHECK = "vocabulary-filter-content-roundtrip-via-download-uri"
GROUP = "data-plane"
SERVICES = ["transcribe"]


@tags("axis:happy-path", "cap:c1", "concern:data-plane", "concern:representation", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """CreateVocabularyFilter stores the submitted words (DANG and HECK appear in the DownloadUri file), and
    after DeleteVocabularyFilter GetVocabularyFilter fails with BadRequestException and the exact not-found
    message."""
    tx = ctx.client("transcribe")
    name = ctx.unique_name("sim2real-behav-filter-")
    tx.create_vocabulary_filter(
        VocabularyFilterName=name,
        LanguageCode="en-US",
        Words=["dang", "heck"],
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _delete_filter_ignore_missing(ctx, name))

    download_uri = _poll_filter_download_uri(ctx, name)
    content = _download(ctx, download_uri).upper()
    assert "DANG" in content, f"submitted word DANG missing from downloaded filter content: {content!r}"
    assert "HECK" in content, f"submitted word HECK missing from downloaded filter content: {content!r}"

    tx.delete_vocabulary_filter(VocabularyFilterName=name)
    code, message = _get_filter_error(ctx, name)
    assert code == "BadRequestException", f"expected BadRequestException reading a deleted filter, got {code}"
    expected = (
        "The requested vocabulary filter couldn't be found. "
        "Check the vocabulary filter name and try your request again."
    )
    assert message == expected, f"expected not-found message {expected!r}, got {message!r}"


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


def _get_filter_error(ctx, name: str) -> tuple:
    tx = ctx.client("transcribe")
    try:
        tx.get_vocabulary_filter(VocabularyFilterName=name)
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"get_vocabulary_filter({name}) unexpectedly succeeded after delete")


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
