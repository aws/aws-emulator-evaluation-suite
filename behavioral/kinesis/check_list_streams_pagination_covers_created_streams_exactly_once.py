"""list-streams-pagination-covers-created-streams-exactly-once."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags


def _poll(probe, pred, timeout_s=60, interval_s=1.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if pred(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _create_stream_with_retry(c, name, **params):
    last_exc = None
    for attempt in range(12):
        try:
            c.create_stream(StreamName=name, Tags={"sim2real": "ga-depth-kinesis"}, **params)
            return
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "LimitExceededException":
                raise
            last_exc = exc
            time.sleep(min(5 + attempt * 2, 15))
    raise AssertionError(f"CreateStream kept hitting LimitExceededException for {name}: {last_exc}")


def _wait_stream_active(c, name, timeout_s=150, interval_s=2):
    _poll(
        lambda: c.describe_stream_summary(StreamName=name)["StreamDescriptionSummary"]["StreamStatus"],
        lambda status: status == "ACTIVE",
        timeout_s, interval_s, f"stream {name} ACTIVE",
    )


CHECK = "list-streams-pagination-covers-created-streams-exactly-once"
GROUP = 'listing'
SERVICES = ['kinesis']


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListStreams' Limit/ExclusiveStartStreamName walk visits each created stream once, in order.

    HasMoreStreams is true while a later page still holds one of them; other streams in the
    account are never counted, only the order of three streams sharing a random prefix."""
    c = ctx.client("kinesis")
    base = ctx.unique_name("sim2real-behav-kds-lsp-")
    names = [f"{base}-a", f"{base}-b", f"{base}-c"]
    for name in names:
        _create_stream_with_retry(c, name, ShardCount=1)
        ctx.on_cleanup(lambda n=name: c.delete_stream(StreamName=n, EnforceConsumerDeletion=True))
    for name in names:
        _wait_stream_active(c, name)

    def _page(limit, start=None):
        kwargs = {"Limit": limit}
        if start is not None:
            kwargs["ExclusiveStartStreamName"] = start
        resp = c.list_streams(**kwargs)
        assert len(resp["StreamNames"]) <= limit, (
            f"ListStreams(Limit={limit}) returned {len(resp['StreamNames'])} names, "
            f"more than the requested cap: {resp['StreamNames']!r}"
        )
        assert set(s["StreamName"] for s in resp["StreamSummaries"]) == set(resp["StreamNames"]), (
            f"StreamSummaries {sorted(s['StreamName'] for s in resp['StreamSummaries'])} must "
            f"name exactly the same streams as StreamNames {sorted(resp['StreamNames'])}"
        )
        return resp

    # Page 1: starting the cursor at `base` itself (never a real stream name) must land on
    # names[0], because "base" < "base-a" < "base-b" < "base-c" lexicographically and nothing
    # else in the account can share this run's random suffix.
    page1 = _page(1, start=base)
    assert page1["StreamNames"] == [names[0]], (
        f"ListStreams(Limit=1, ExclusiveStartStreamName={base!r}) returned "
        f"{page1['StreamNames']!r}, expected exactly [{names[0]!r}] as the first page"
    )
    assert page1["HasMoreStreams"] is True, (
        f"HasMoreStreams must be True on page 1: this check's own streams {names[1:]} are known "
        f"to sort after {names[0]!r} and were not yet returned, got {page1['HasMoreStreams']!r}"
    )

    # Page 2: ExclusiveStartStreamName=names[0] must be EXCLUSIVE of names[0] itself.
    page2 = _page(1, start=names[0])
    assert page2["StreamNames"] == [names[1]], (
        f"ListStreams(Limit=1, ExclusiveStartStreamName={names[0]!r}) returned "
        f"{page2['StreamNames']!r}, expected exactly [{names[1]!r}] — the cursor name itself "
        f"must not reappear"
    )
    assert page2["HasMoreStreams"] is True, (
        f"HasMoreStreams must be True on page 2: {names[2]!r} is known to sort after "
        f"{names[1]!r} and was not yet returned, got {page2['HasMoreStreams']!r}"
    )

    # Page 3: a Limit larger than what remains must still surface the last stream next.
    page3 = _page(5, start=names[1])
    assert page3["StreamNames"][:1] == [names[2]], (
        f"ListStreams(Limit=5, ExclusiveStartStreamName={names[1]!r}) must surface "
        f"{names[2]!r} as the very next name, got {page3['StreamNames']!r}"
    )
    # HasMoreStreams here depends on unrelated streams sorting after names[2], so only its
    # type is asserted.
    assert isinstance(page3["HasMoreStreams"], bool), (
        f"HasMoreStreams must be a bool, got {page3['HasMoreStreams']!r}"
    )

    # A single Limit=3 page starting at `base` must return this check's three streams, in
    # the same order, as one page — proving Limit and the cursor compose rather than only
    # working one at a time.
    one_page = _page(3, start=base)
    assert one_page["StreamNames"][:3] == names, (
        f"ListStreams(Limit=3, ExclusiveStartStreamName={base!r}) must return {names!r} as "
        f"the first three names, got {one_page['StreamNames']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
