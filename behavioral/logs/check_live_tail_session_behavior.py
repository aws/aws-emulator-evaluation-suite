"""live-tail-session-behavior."""
from __future__ import annotations

import queue
import threading
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "live-tail-session-behavior"
GROUP = 'log-events'
SERVICES = ['logs']


def _error_code(fn):
    """The AWS (code, message) fn() raised. An unexpected SUCCESS raises, so a target that
    accepts what AWS refuses never reads as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"the call was expected to be refused but it succeeded, returning {result!r}")


def _describe_log_group(svc, name):
    desc = svc.describe_log_groups(logGroupNamePrefix=name)
    for g in desc.get("logGroups", []):
        if g["logGroupName"] == name:
            return g
    raise AssertionError(f"log group {name!r} not found via DescribeLogGroups")


def _read_live_tail_events(stream, *, max_events=1, timeout_s=30):
    """Read up to ``max_events`` frames off a StartLiveTail responseStream.

    Runs the blocking iterator in a background thread so a hung/slow stream
    can't wedge the check past ``timeout_s``.
    """
    q: queue.Queue = queue.Queue()

    def _reader():
        try:
            for event in stream:
                q.put(("event", event))
        except Exception as exc:  # noqa: BLE001
            q.put(("error", exc))
        finally:
            q.put(("done", None))

    t = threading.Thread(target=_reader, daemon=True)
    t.start()

    collected: list = []
    deadline = time.time() + timeout_s
    while len(collected) < max_events and time.time() < deadline:
        remaining = max(0.1, deadline - time.time())
        try:
            kind, payload = q.get(timeout=remaining)
        except Exception:  # noqa: BLE001
            break
        if kind == "event":
            collected.append(payload)
        elif kind == "error":
            raise AssertionError(f"live tail stream raised: {payload!r}")
        elif kind == "done":
            break
    return collected


@tags("axis:happy-path", "cap:c6", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """StartLiveTail's first frame is sessionStart naming the resolved group, later frames are
    sessionUpdate heartbeats, and a malformed group identifier is refused with ResourceNotFoundException
    and its exact message.
    """
    svc = ctx.client("logs")
    account = ctx.client("sts").get_caller_identity()["Account"]

    group = ctx.unique_name("sim2real-behav-lg-livetail-")
    svc.create_log_group(logGroupName=group, tags={"Sim2RealOwner": "behavioral-suite"})
    ctx.on_cleanup(lambda _n=group: svc.delete_log_group(logGroupName=_n))
    group_arn = _describe_log_group(svc, group)["logGroupArn"]

    try:
        resp = svc.start_live_tail(logGroupIdentifiers=[group_arn])
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code") or type(exc).__name__
        raise AssertionError(f"StartLiveTail streaming session not runnable on this endpoint ({code})") from exc
    stream = resp.get("responseStream")
    if stream is None:
        raise AssertionError("StartLiveTail did not return a responseStream on this endpoint")

    frames = _read_live_tail_events(stream, max_events=3, timeout_s=20)
    assert frames, "StartLiveTail never delivered a single frame within the timeout"
    assert "sessionStart" in frames[0], f"expected sessionStart as the first frame, got {frames[0]!r}"
    resolved = frames[0]["sessionStart"].get("logGroupIdentifiers", [])
    assert group_arn in resolved, f"expected our log group ARN among resolved identifiers: {resolved!r}"

    # A session that only ever emits its one sessionStart frame and then goes quiet is
    # a one-shot response wearing a streaming API, not a live session -- so at least one
    # more frame is REQUIRED within the window (documented per-second heartbeat cadence),
    # not merely tolerated if it happens to show up.
    assert len(frames) >= 2, (
        f"expected at least one sessionUpdate heartbeat after sessionStart within 20s, "
        f"got only {len(frames)} frame(s): {frames!r}"
    )
    for extra in frames[1:]:
        assert "sessionUpdate" in extra, (
            f"expected subsequent frames to be sessionUpdate heartbeats, got {extra!r}"
        )
        assert "sessionStart" not in extra, "got a second sessionStart on an already-open session"

    stream.close()

    bogus_arn = (
        f"arn:aws:logs:{ctx.region}:{account}:log-group:"
        f"{ctx.unique_name('sim2real-behav-lg-livetail-missing-')}"
    )
    code, code_msg = _error_code(lambda: svc.start_live_tail(logGroupIdentifiers=[bogus_arn]))
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code!r}"
    expected = "Provided LogGroup doesn't exist."
    assert code_msg == expected, f"expected message {expected!r}, got {code_msg!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
