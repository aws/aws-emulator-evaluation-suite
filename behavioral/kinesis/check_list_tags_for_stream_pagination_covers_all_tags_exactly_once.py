"""list-tags-for-stream-pagination-covers-all-tags-exactly-once."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-tags-for-stream-pagination-covers-all-tags-exactly-once"
GROUP = "tagging"
SERVICES = ["kinesis"]


def _wait_stream_active(kinesis, stream_name, timeout_s=120.0):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        status = kinesis.describe_stream_summary(StreamName=stream_name)["StreamDescriptionSummary"]["StreamStatus"]
        if status == "ACTIVE":
            return
        time.sleep(2)
    raise AssertionError(f"stream {stream_name} never became ACTIVE within {timeout_s}s")


def _until_all_tags_visible(kinesis, stream_name, wanted_keys, timeout_s=60.0, interval_s=2.0):
    """Tag writes can lag ListTagsForStream; poll the unpaginated read until every key is present."""
    deadline = time.monotonic() + timeout_s
    seen = set()
    while time.monotonic() < deadline:
        seen = {t["Key"] for t in kinesis.list_tags_for_stream(StreamName=stream_name)["Tags"]}
        if wanted_keys <= seen:
            return
        time.sleep(interval_s)
    raise AssertionError(f"tags {sorted(wanted_keys - seen)} never became visible within {timeout_s}s")


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListTagsForStream paged with Limit and ExclusiveStartTagKey visits every tag exactly once
    and sets HasMoreTags only while a further page remains."""
    kinesis = ctx.client("kinesis")
    name = ctx.unique_name("sim2real-behav-ltp-")

    kinesis.create_stream(StreamName=name, StreamModeDetails={"StreamMode": "ON_DEMAND"})
    ctx.on_cleanup(lambda: kinesis.delete_stream(StreamName=name, EnforceConsumerDeletion=True))
    _wait_stream_active(kinesis, name)

    wanted = {f"sim2real-ltp-key-{i}": f"value-{i}" for i in range(4)}
    kinesis.add_tags_to_stream(StreamName=name, Tags=wanted)
    _until_all_tags_visible(kinesis, name, set(wanted))

    pages = []
    start_key = None
    for _ in range(len(wanted) + 1):
        kwargs = {"StreamName": name, "Limit": 1}
        if start_key is not None:
            kwargs["ExclusiveStartTagKey"] = start_key
        resp = kinesis.list_tags_for_stream(**kwargs)
        page_tags = resp["Tags"]
        assert len(page_tags) == 1, f"Limit=1 must cap a page at one tag, got {page_tags!r}"
        pages.append((page_tags[0]["Key"], page_tags[0]["Value"], resp["HasMoreTags"]))
        start_key = page_tags[0]["Key"]
        if not resp["HasMoreTags"]:
            break
    else:
        raise AssertionError(f"pagination never set HasMoreTags=False within {len(wanted) + 1} pages")

    assert len(pages) == len(wanted), (
        f"a stream with {len(wanted)} tags paged at Limit=1 must take {len(wanted)} pages, "
        f"took {len(pages)}: {pages!r}"
    )
    has_more_flags = [p[2] for p in pages]
    assert has_more_flags == [True] * (len(pages) - 1) + [False], (
        f"HasMoreTags must be True on every page but the last, got {has_more_flags!r}"
    )
    collected = {key: value for key, value, _ in pages}
    assert collected == wanted, (
        f"the walked pages must cover {wanted!r} exactly once each, got {collected!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
