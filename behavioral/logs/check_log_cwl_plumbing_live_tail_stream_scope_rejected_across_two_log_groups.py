"""log-cwl-plumbing-live-tail-stream-scope-rejected-across-two-log-groups."""
from __future__ import annotations

import threading
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "log-cwl-plumbing-live-tail-stream-scope-rejected-across-two-log-groups"
GROUP = "live-tail"
SERVICES = ["logs"]


@tags(
    "axis:rejection",
    "cap:c1",
    "cap:c6",
    "concern:data-plane",
    "concern:negative-classes",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """StartLiveTail over two log groups rejects logStreamNames and logStreamNamePrefixes with
    InvalidParameterException, while the unscoped two-group and scoped one-group sessions deliver.
    """
    logs = ctx.client("logs")
    account = ctx.client("sts").get_caller_identity()["Account"]

    groups, arns = [], []
    stream = ctx.unique_name("tail-s-")
    for i in (1, 2):
        g = ctx.unique_name(f"sim2real-cwlp-lt2-{i}-")
        logs.create_log_group(logGroupName=g, tags={"sim2real": CHECK})
        ctx.on_cleanup(lambda g=g: logs.delete_log_group(logGroupName=g))
        logs.create_log_stream(logGroupName=g, logStreamName=stream)
        groups.append(g)
        arns.append(_group_arn(logs, g))
    marker = ctx.unique_name("cwlp-lt2-")

    for param, value, named in (
        ("logStreamNames", [stream], "LogStreamNames"),
        ("logStreamNamePrefixes", [stream[:8]], "LogStreamPrefixes"),
    ):
        try:
            resp = logs.start_live_tail(logGroupIdentifiers=arns, **{param: value})
            _Tail(resp).close()
            raise AssertionError(
                f"expected StartLiveTail over two groups with {param} to be refused, but it "
                f"opened a session"
            )
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            message = exc.response["Error"].get("Message", "")
        assert code == "InvalidParameterException", (
            f"expected InvalidParameterException for {param} over two groups, got {code!r} "
            f"({message!r})"
        )
        expected = (
            f"{named} provided with more than one LogGroupIdentifier. "
            f"{named} is disabled if more than one LogGroupIdentifier is provided."
        )
        assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Positive control: the same two groups, unscoped.
    got = _tail_until(
        ctx, logs, dict(logGroupIdentifiers=arns),
        writes=[(groups[0], stream), (groups[1], stream)], marker=f"{marker} both",
        want_groups={f"{account}:{g}" for g in groups},
    )
    assert {r["logGroupIdentifier"] for r in got} == {f"{account}:{g}" for g in groups}, (
        f"expected lines from both groups in the unscoped session, got {got!r}"
    )

    # Positive control: the same logStreamNames over one group.
    got = _tail_until(
        ctx, logs, dict(logGroupIdentifiers=[arns[1]], logStreamNames=[stream]),
        writes=[(groups[1], stream)], marker=f"{marker} one",
        want_groups={f"{account}:{groups[1]}"},
    )
    assert all(r["logStreamName"] == stream for r in got), f"wrong stream pushed: {got!r}"


def _now_ms() -> int:
    return int(time.time() * 1000)


def _tail_until(ctx, logs, kwargs: dict, *, writes, marker: str, want_groups: set[str]):
    """Open a session and rewrite numbered lines to every (group, stream) until each wanted
    group has pushed one of this session's lines (bounded), then close it."""
    session = _Tail(logs.start_live_tail(**kwargs))
    try:
        session.wait_start(30.0)
        deadline = time.monotonic() + 120.0
        attempt = 0
        while time.monotonic() < deadline:
            mine = [r for r in session.results() if r.get("message", "").startswith(marker)]
            if {r["logGroupIdentifier"] for r in mine} >= want_groups:
                return mine
            attempt += 1
            for g, s in writes:
                logs.put_log_events(
                    logGroupName=g,
                    logStreamName=s,
                    logEvents=[{"timestamp": _now_ms(), "message": f"{marker} {attempt} {g}"}],
                )
            time.sleep(4.0)
    finally:
        session.close()
    raise AssertionError(
        f"session {kwargs!r} never pushed a {marker!r} line from each of {sorted(want_groups)!r} "
        f"in {attempt} rounds; got {session.results()!r}"
    )


def _group_arn(logs, group: str) -> str:
    """DescribeLogGroups returns the ARN with a trailing ':*'; StartLiveTail rejects it."""
    arns = [
        g["arn"]
        for page in logs.get_paginator("describe_log_groups").paginate(logGroupNamePrefix=group)
        for g in page.get("logGroups", [])
        if g["logGroupName"] == group
    ]
    assert len(arns) == 1, f"expected one log group named {group!r}, got {arns!r}"
    return arns[0][: -len(":*")] if arns[0].endswith(":*") else arns[0]


class _Tail:
    """Consume a StartLiveTail response stream on a daemon thread."""

    def __init__(self, resp) -> None:
        self._stream = resp["responseStream"]
        self._started = threading.Event()
        self._results: list[dict] = []
        self._lock = threading.Lock()
        self._thread = threading.Thread(target=self._consume, daemon=True)
        self._thread.start()

    def _consume(self) -> None:
        try:
            for event in self._stream:
                if "sessionStart" in event:
                    self._started.set()
                elif "sessionUpdate" in event:
                    with self._lock:
                        self._results.extend(event["sessionUpdate"].get("sessionResults", []))
        except Exception:  # noqa: BLE001 - a closed session just ends the consumer
            return

    def wait_start(self, timeout_s: float) -> None:
        assert self._started.wait(timeout=timeout_s), (
            f"StartLiveTail never delivered sessionStart within {timeout_s}s"
        )

    def results(self) -> list[dict]:
        with self._lock:
            return list(self._results)

    def close(self) -> None:
        try:
            self._stream.close()
        except Exception:  # noqa: BLE001 - the session may already have ended
            pass


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
