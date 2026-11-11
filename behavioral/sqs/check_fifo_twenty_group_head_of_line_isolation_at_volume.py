"""fifo-twenty-group-head-of-line-isolation-at-volume."""
from __future__ import annotations

import collections
import random
import threading
import time
from concurrent.futures import ThreadPoolExecutor

from behavioral_harness import tags

CHECK = "fifo-twenty-group-head-of-line-isolation-at-volume"
GROUP = 'fifo'
SERVICES = ['sqs']

GROUPS = [f"g{i:02d}" for i in range(20)]
PER_GROUP = 25
TOTAL = len(GROUPS) * PER_GROUP          # 500
DRAIN_DEADLINE_S = 240.0
DRAIN_IDLE_S = 8.0          # a receiver gives up after this long seeing only empty receives

_TAGS = {"sim2real:managed": "true", "sim2real": "fifo-twenty-group-head-of-line-isolation-at-volume"}


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _make_queue(sqs, ctx) -> str:
    """A FIFO queue whose in-flight window is long enough that a held head stays held."""
    url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-behav-d5-") + ".fifo",
        Attributes={"FifoQueue": "true", "ContentBasedDeduplication": "true",
                    "VisibilityTimeout": "600", "ReceiveMessageWaitTimeSeconds": "0"},
        tags=_TAGS,
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    return url


def _body(group: str, ordinal: int, arm: str) -> str:
    return f"{arm}|{group}|{ordinal:02d}"


def _parse(body: str) -> tuple[str, int]:
    _arm, group, ordinal = body.split("|")
    return group, int(ordinal)


def _send_interleaved(sqs, url: str, arm: str) -> dict[str, list[str]]:
    """Send 500 messages, index i -> group i % 20, ordinal i // 20.

    Consecutive sends never share a group, so global and per-group order disagree.
    """
    seqs: dict[str, list[str]] = collections.defaultdict(list)
    for base in range(0, TOTAL, 10):
        entries = []
        for i in range(base, base + 10):
            group = GROUPS[i % len(GROUPS)]
            entries.append({"Id": f"e{i - base}",
                            "MessageBody": _body(group, i // len(GROUPS), arm),
                            "MessageGroupId": group})
        resp = sqs.send_message_batch(QueueUrl=url, Entries=entries)
        failed = resp.get("Failed", [])
        assert not failed, f"send_message_batch at base {base} reported failures {failed!r}"
        assert len(resp["Successful"]) == 10, (
            f"send_message_batch at base {base} acknowledged {len(resp['Successful'])} of 10"
        )
        for entry in resp["Successful"]:
            i = base + int(entry["Id"][1:])
            seqs[GROUPS[i % len(GROUPS)]].append(entry["SequenceNumber"])
    return seqs


def _drain(ctx, sqs, url: str, want: int, workers: int = 8) -> list[tuple[int, str, int]]:
    """Drain with `workers` concurrent receivers; return (arrival_index, group, ordinal) tuples.

    The arrival index lets verdicts order within a group; SQS does not define cross-group order.
    """
    seen: list[tuple[int, str, int]] = []
    lock = threading.Lock()
    deadline = time.monotonic() + _budget_s(ctx, DRAIN_DEADLINE_S)
    state = {"idx": 0, "multi_group_calls": 0}
    done = threading.Event()

    def receive_loop() -> None:
        idle_since = None
        while time.monotonic() < deadline and not done.is_set():
            resp = sqs.receive_message(
                QueueUrl=url, MaxNumberOfMessages=10, WaitTimeSeconds=1,
                MessageSystemAttributeNames=["MessageGroupId"],
            )
            msgs = resp.get("Messages", [])
            if not msgs:
                if idle_since is None:
                    idle_since = time.monotonic()
                elif time.monotonic() - idle_since >= DRAIN_IDLE_S:
                    return
                continue
            idle_since = None
            with lock:
                if len({m["Attributes"]["MessageGroupId"] for m in msgs}) > 1:
                    state["multi_group_calls"] += 1
                for m in msgs:
                    group, ordinal = _parse(m["Body"])
                    assert m["Attributes"]["MessageGroupId"] == group, (
                        f"MessageGroupId system attribute {m['Attributes']['MessageGroupId']!r} "
                        f"does not match the group encoded in the body {m['Body']!r}"
                    )
                    seen.append((state["idx"], group, ordinal))
                    state["idx"] += 1
            sqs.delete_message_batch(QueueUrl=url, Entries=[
                {"Id": f"d{i}", "ReceiptHandle": m["ReceiptHandle"]} for i, m in enumerate(msgs)])
            with lock:
                if len(seen) >= want:
                    done.set()

    with ThreadPoolExecutor(max_workers=workers) as pool:
        for fut in [pool.submit(receive_loop) for _ in range(workers)]:
            fut.result()

    if len(seen) < want and _budget_spent(ctx):
        raise TimeoutError(f"draining {want} messages: the run budget ended first; not graded")
    return seen


def _verdict(observations: list[tuple[int, str, int]]) -> tuple:
    """(count, distinct, per-group order), independent of the order of `observations`.

    Ordering uses each observation's arrival index, so a shuffled copy gives the same verdict.
    """
    per_group: dict[str, list[tuple[int, int]]] = collections.defaultdict(list)
    for idx, group, ordinal in observations:
        per_group[group].append((idx, ordinal))
    ordered = {g: tuple(o for _i, o in sorted(v)) for g, v in per_group.items()}
    return (
        len(observations),
        len({(g, o) for _i, g, o in observations}),
        tuple(sorted(ordered.items())),
    )


def _await_counters(ctx, sqs, url: str, visible: int, in_flight: int) -> dict[str, str]:
    """Poll the queue counters until they reach the expected pair, or fail with what we saw."""
    attrs: dict[str, str] = {}
    deadline = time.monotonic() + _budget_s(ctx, 60)
    while time.monotonic() < deadline:
        attrs = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=[
            "ApproximateNumberOfMessages", "ApproximateNumberOfMessagesNotVisible",
        ])["Attributes"]
        if (attrs["ApproximateNumberOfMessages"] == str(visible)
                and attrs["ApproximateNumberOfMessagesNotVisible"] == str(in_flight)):
            return attrs
        time.sleep(1)
    if _budget_spent(ctx):
        raise TimeoutError(
            f"queue counters reaching visible={visible} in_flight={in_flight}: the run budget ended first; not graded"
        )
    raise AssertionError(
        f"queue counters never reached visible={visible} in_flight={in_flight}; last read {attrs!r}"
    )


def _hold_group_head(ctx, sqs, url: str, group: str) -> dict:
    """Receive one message at a time until `group`'s head arrives; keep it in flight.

    Other messages are returned via ChangeMessageVisibility(0), not deleted, so TOTAL - 1 remain.
    """
    deadline = time.monotonic() + _budget_s(ctx, 240.0)
    for _ in range(120):
        if time.monotonic() >= deadline:
            break
        resp = sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=1, WaitTimeSeconds=2,
                                   MessageSystemAttributeNames=["MessageGroupId"])
        msgs = resp.get("Messages", [])
        if not msgs:
            continue
        msg = msgs[0]
        got_group, ordinal = _parse(msg["Body"])
        if got_group == group:
            assert ordinal == 0, (
                f"the first message ever delivered for group {group!r} was ordinal {ordinal}, "
                f"not its head (0) — per-group FIFO order was violated before the stall began"
            )
            return msg
        sqs.change_message_visibility(QueueUrl=url, ReceiptHandle=msg["ReceiptHandle"],
                                      VisibilityTimeout=0)
    if _budget_spent(ctx):
        raise TimeoutError(f"receiving group {group!r}'s head: the run budget ended first; not graded")
    raise AssertionError(f"never received a message for group {group!r} in up to 120 single receives")


@tags("axis:happy-path", "cap:c2", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """Holding one FIFO group's head blocks exactly that group and nothing else, at volume.

    With 20 groups, 0/1/2 held heads drain 500/475/450 messages, each group in order.
    """
    sqs = ctx.client("sqs")
    rng = random.Random(0)
    expect_all = {g: tuple(range(PER_GROUP)) for g in GROUPS}

    # Nothing held: the baseline that makes the stall arms' shortfall attributable.
    control_url = _make_queue(sqs, ctx)
    _send_interleaved(sqs, control_url, "control")
    control_obs = _drain(ctx, sqs, control_url, TOTAL)
    c_count, c_distinct, c_ordered = _verdict(control_obs)
    assert c_count == TOTAL, (
        f"control arm drained {c_count} of {TOTAL} with nothing held — the 475 below would not "
        f"be attributable to the stall"
    )
    assert c_distinct == TOTAL, f"control arm delivered duplicates: {c_count} received, {c_distinct} distinct"
    assert dict(c_ordered) == expect_all, (
        "control arm broke per-group order: "
        f"{ {g: v for g, v in c_ordered if v != expect_all.get(g)} !r}"
    )

    # One head held: 19 groups must drain completely; the 20th must not move.
    one_url = _make_queue(sqs, ctx)
    seqs = _send_interleaved(sqs, one_url, "one")
    for group, group_seqs in sorted(seqs.items()):
        assert len(group_seqs) == PER_GROUP, (
            f"group {group!r} was acknowledged {len(group_seqs)} times, expected {PER_GROUP}"
        )
        as_ints = [int(s) for s in group_seqs]
        assert all(a < b for a, b in zip(as_ints, as_ints[1:])), (
            f"group {group!r} SequenceNumbers are not strictly increasing in send order: {group_seqs!r}"
        )

    held = _hold_group_head(ctx, sqs, one_url, "g00")
    _await_counters(ctx, sqs, one_url, TOTAL - 1, 1)

    one_obs = _drain(ctx, sqs, one_url, TOTAL - PER_GROUP)
    count, distinct, ordered = _verdict(one_obs)
    expect_19 = {g: tuple(range(PER_GROUP)) for g in GROUPS if g != "g00"}
    assert count == TOTAL - PER_GROUP, (
        f"with g00's head in flight, 19 groups drained {count} messages, expected "
        f"{TOTAL - PER_GROUP}; groups seen were {sorted({g for _i, g, _o in one_obs})!r}"
    )
    assert "g00" not in {g for _i, g, _o in one_obs}, (
        "a message from the stalled group g00 was delivered while its head was in flight: "
        f"{sorted(o for _i, g, o in one_obs if g == 'g00')!r}"
    )
    assert distinct == TOTAL - PER_GROUP, (
        f"8 concurrent receivers delivered duplicates: {count} received, {distinct} distinct"
    )
    assert dict(ordered) == expect_19, (
        "per-group order or completeness broke under 8 concurrent receivers: "
        f"{ {g: v for g, v in ordered if v != expect_19.get(g)} !r}"
    )

    # Shuffle invariance: the verdict must not depend on the cross-group interleaving.
    shuffled = rng.sample(one_obs, len(one_obs))
    assert shuffled != one_obs, "shuffle produced the identical list; the invariance test would be vacuous"
    assert _verdict(shuffled) == (count, distinct, ordered), (
        "the verdict function is NOT shuffle-invariant, so this check depends on the order in "
        "which groups interleaved — which SQS does not define"
    )

    # Counters model per-group state too: the 24 blocked siblings are VISIBLE, not in flight.
    _await_counters(ctx, sqs, one_url, PER_GROUP - 1, 1)

    # Release the head: the stalled group's remaining 24 arrive, in order, behind it.
    sqs.delete_message(QueueUrl=one_url, ReceiptHandle=held["ReceiptHandle"])
    released = _drain(ctx, sqs, one_url, PER_GROUP - 1, workers=1)
    r_count, _r_distinct, r_ordered = _verdict(released)
    assert r_count == PER_GROUP - 1, (
        f"after deleting the held head, {r_count} messages drained, expected {PER_GROUP - 1}"
    )
    assert dict(r_ordered) == {"g00": tuple(range(1, PER_GROUP))}, (
        f"the released group drained as {dict(r_ordered)!r}, expected g00 ordinals 1..{PER_GROUP - 1}"
    )

    # Two heads held: the isolation is per group, not one special group.
    two_url = _make_queue(sqs, ctx)
    _send_interleaved(sqs, two_url, "two")
    held_a = _hold_group_head(ctx, sqs, two_url, "g00")
    held_b = _hold_group_head(ctx, sqs, two_url, "g07")
    assert held_a["ReceiptHandle"] != held_b["ReceiptHandle"], (
        f"holding g00 and g07 yielded the SAME receipt handle {held_a['ReceiptHandle']!r} — "
        f"the two stalled heads were not actually distinct in-flight messages"
    )
    two_obs = _drain(ctx, sqs, two_url, TOTAL - 2 * PER_GROUP)
    t_count, t_distinct, t_ordered = _verdict(two_obs)
    expect_18 = {g: tuple(range(PER_GROUP)) for g in GROUPS if g not in ("g00", "g07")}
    assert t_count == TOTAL - 2 * PER_GROUP, (
        f"with two heads in flight, {t_count} messages drained, expected {TOTAL - 2 * PER_GROUP}"
    )
    assert t_distinct == t_count, f"two-stall arm delivered duplicates: {t_count} vs {t_distinct} distinct"
    assert dict(t_ordered) == expect_18, (
        "two-stall arm: 18 groups did not drain completely and in order: "
        f"{ {g: v for g, v in t_ordered if v != expect_18.get(g)} !r}"
    )
    assert _verdict(rng.sample(two_obs, len(two_obs))) == (t_count, t_distinct, t_ordered), (
        "the two-stall verdict is not shuffle-invariant"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
