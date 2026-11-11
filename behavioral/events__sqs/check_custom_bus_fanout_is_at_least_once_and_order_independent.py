"""custom-bus-fanout-is-at-least-once-and-order-independent."""
from __future__ import annotations

import collections
import json
import random
import time
from concurrent.futures import ThreadPoolExecutor

from behavioral_harness import tags

CHECK = "custom-bus-fanout-is-at-least-once-and-order-independent"
GROUP = 'fanout'
SERVICES = ['events', 'sqs']

N_EVENTS = 1000
N_TENANTS = 20
SOURCE = "sim2real.d5"
DETAIL_TYPE = "sim2real.ordering"
DRAIN_DEADLINE_S = 300.0

# `sim2real:managed=true` marks every resource for account cleanup, which discovers resources
# through the Resource Groups Tagging API.
_TAGS = {"sim2real:managed": "true", "sim2real": "custom-bus-fanout"}
_TAGS_KV = [{"Key": k, "Value": v} for k, v in _TAGS.items()]

#: Four independent pattern semantics over one event space. `prefix` and `anything-but` are
#: complementary on the tenant field, so R1 and R4 must partition the 1,000 events between
#: them — an engine that ignores `anything-but` passes R1 and fails that partition.
PATTERNS = {
    "r1": {"source": [SOURCE], "detail": {"tenant": [{"prefix": "t-000"}]}},
    "r2": {"source": [SOURCE], "detail": {"n": [{"numeric": [">=", 500]}]}},
    "r3": {"source": [SOURCE], "detail-type": [DETAIL_TYPE]},
    "r4": {"source": [SOURCE], "detail": {"tenant": [{"anything-but": ["t-000"]}]}},
}
PREDICATES = {
    "r1": lambda tenant, n: tenant.startswith("t-000"),
    "r2": lambda tenant, n: n >= 500,
    "r3": lambda tenant, n: True,
    "r4": lambda tenant, n: tenant != "t-000",
}
EXPECTED_SIZES = {"r1": 50, "r2": 500, "r3": 1000, "r4": 950}


def _queue(sqs, ctx, region: str, account: str, bus: str) -> tuple[str, str]:
    url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-behav-d5-"), tags=_TAGS)["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    arn = sqs.get_queue_attributes(
        QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    sqs.set_queue_attributes(QueueUrl=url, Attributes={"Policy": json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Sid": "AllowEventBridge", "Effect": "Allow",
            "Principal": {"Service": "events.amazonaws.com"},
            "Action": "sqs:SendMessage", "Resource": arn,
            "Condition": {"ArnLike": {
                "aws:SourceArn": f"arn:aws:events:{region}:{account}:rule/{bus}/*"}},
        }],
    })})
    return url, arn


def _publish(ev, bus: str, payloads: list[tuple[str, str, int]]) -> None:
    """Publish in batches of 10; every batch must be wholly accepted."""
    for base in range(0, len(payloads), 10):
        batch = payloads[base:base + 10]
        resp = ev.put_events(Entries=[
            {"EventBusName": bus, "Source": SOURCE, "DetailType": DETAIL_TYPE,
             "Detail": json.dumps({"tenant": tenant, "n": n, "id": event_id})}
            for event_id, tenant, n in batch])
        assert resp["FailedEntryCount"] == 0, (
            f"put_events at offset {base} reported {resp['FailedEntryCount']} failures: {resp!r}"
        )
        assert len(resp["Entries"]) == len(batch), (
            f"put_events at offset {base} returned {len(resp['Entries'])} entries for "
            f"{len(batch)} events"
        )
        assert all(entry.get("EventId") for entry in resp["Entries"]), (
            f"put_events at offset {base} returned an entry with no EventId: {resp['Entries']!r}"
        )


def _receive(sqs, url: str, wait: int = 5) -> list[dict]:
    resp = sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=10, WaitTimeSeconds=wait)
    msgs = resp.get("Messages", [])
    if msgs:
        sqs.delete_message_batch(QueueUrl=url, Entries=[
            {"Id": f"d{i}", "ReceiptHandle": m["ReceiptHandle"]} for i, m in enumerate(msgs)])
    return msgs


def _event_id(message: dict) -> str:
    """The id we published, parsed structurally out of the SNS-less EventBridge envelope."""
    return json.loads(message["Body"])["detail"]["id"]


def _drain(sqs, url: str, want: int, deadline: float) -> list[str]:
    got: list[str] = []
    idle = 0
    while time.monotonic() < deadline and len(got) < want:
        msgs = _receive(sqs, url)
        if not msgs:
            idle += 1
            if idle >= 8:
                return got
            continue
        idle = 0
        got += [_event_id(m) for m in msgs]
    return got


def _drain_empty(sqs, url: str) -> None:
    """Drain to two consecutive empty receives, so a later arrival is a real arrival."""
    empties = 0
    deadline = time.monotonic() + 120
    while time.monotonic() < deadline and empties < 2:
        empties = empties + 1 if not _receive(sqs, url, wait=2) else 0
    assert empties >= 2, f"queue {url!r} would not drain to empty inside 120 s"


def _warm_up(ev, sqs, bus: str, urls: dict[str, str]) -> None:
    """Publish throwaway events until every queue has proven it can receive one.

    An SQS resource policy becomes effective asynchronously and exposes no condition to poll,
    and EventBridge drops — silently, with FailedEntryCount 0 — anything it cannot deliver. So
    the warm-up is a bounded retry against an OBSERVABLE condition (a message arriving), not a
    sleep. Two tenants are used because R1 (prefix t-000) and R4 (anything-but t-000) are
    complementary by construction, so no single event can reach all four queues.
    """
    confirmed: set[str] = set()
    deadline = time.monotonic() + 240
    round_no = 0
    while time.monotonic() < deadline and confirmed != set(urls):
        _publish(ev, bus, [(f"warm-{round_no}-a", "t-000", 999),
                           (f"warm-{round_no}-b", "t-001", 999)])
        round_no += 1
        for _ in range(4):
            for rule, url in urls.items():
                if _receive(sqs, url, wait=2):
                    confirmed.add(rule)
            if confirmed == set(urls):
                break
    assert confirmed == set(urls), (
        f"only {sorted(confirmed)} of {sorted(urls)} queues ever received a warm-up event, so "
        f"a later absence could not be attributed to a pattern"
    )
    for url in urls.values():
        _drain_empty(sqs, url)


def _verdict(observed: list[str]) -> tuple:
    """The verdict over one rule's deliveries, by construction independent of arrival order.

    EventBridge is at-least-once and guarantees NO ordering, so the only defensible verdict is
    over the multiset's SUPPORT (a duplicate is legal, a drop is not) and its minimum
    multiplicity. Asserting shuffle invariance of this function is what stops a later edit from
    reintroducing an order dependency that real AWS would fail: it is the one mechanical
    defence this axis has against over-strong ordering assertions.
    """
    counted = collections.Counter(observed)
    return (frozenset(counted), min(counted.values(), default=0), len(observed))


@tags(
    "axis:happy-path",
    "cap:c2",
    "cap:c3",
    "concern:eventing",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """1,000 events fan out to four patterns at-least-once, and the verdict ignores order.
    Each rule exercises a different matcher (prefix, numeric range, detail-type, anything-but)
    over the same events, and the prefix and anything-but rules must partition the tenant space."""
    ev = ctx.client("events")
    sqs = ctx.client("sqs")
    account = ctx.client("sts").get_caller_identity()["Account"]

    bus = ctx.unique_name("sim2real-behav-d5-")
    ev.create_event_bus(Name=bus, Tags=_TAGS_KV)
    ctx.on_cleanup(lambda: ev.delete_event_bus(Name=bus))

    urls: dict[str, str] = {}
    for rule, pattern in PATTERNS.items():
        url, arn = _queue(sqs, ctx, ctx.region, account, bus)
        urls[rule] = url
        name = f"{bus}-{rule}"
        ev.put_rule(Name=name, EventBusName=bus, EventPattern=json.dumps(pattern), State="ENABLED")
        ctx.on_cleanup(lambda n=name: ev.delete_rule(Name=n, EventBusName=bus))
        resp = ev.put_targets(Rule=name, EventBusName=bus, Targets=[{"Id": "q", "Arn": arn}])
        ctx.on_cleanup(lambda n=name: ev.remove_targets(Rule=n, EventBusName=bus, Ids=["q"]))
        assert resp["FailedEntryCount"] == 0, (
            f"put_targets for {rule} failed: {resp.get('FailedEntries')!r}"
        )

    _warm_up(ev, sqs, bus, urls)

    published: list[tuple[str, str, int]] = []
    expected: dict[str, set[str]] = {rule: set() for rule in PATTERNS}
    for i in range(N_EVENTS):
        tenant = f"t-{i % N_TENANTS:03d}"
        event_id = f"{bus}-{i:04d}"
        published.append((event_id, tenant, i))
        for rule, predicate in PREDICATES.items():
            if predicate(tenant, i):
                expected[rule].add(event_id)
    assert {rule: len(ids) for rule, ids in expected.items()} == EXPECTED_SIZES, (
        f"the in-check predicates select {({r: len(v) for r, v in expected.items()})!r}, "
        f"expected {EXPECTED_SIZES!r} — the workload no longer discriminates the four patterns"
    )
    _publish(ev, bus, published)

    deadline = time.monotonic() + DRAIN_DEADLINE_S
    with ThreadPoolExecutor(max_workers=12) as pool:
        futures = {rule: [pool.submit(_drain, sqs, url, len(expected[rule]), deadline)
                          for _ in range(3)] for rule, url in urls.items()}
        observed = {rule: [i for f in fs for i in f.result()] for rule, fs in futures.items()}

    all_ids = {event_id for event_id, _t, _n in published}
    verdicts = {}
    for rule in PATTERNS:
        got = observed[rule]
        support, min_multiplicity, total = _verdict(got)
        verdicts[rule] = (support, min_multiplicity, total)
        missing = expected[rule] - support
        foreign = support - expected[rule]
        assert not missing, (
            f"{rule} is missing {len(missing)} of {len(expected[rule])} expected events; "
            f"first missing {sorted(missing)[:5]!r}"
        )
        assert not foreign, (
            f"{rule} received {len(foreign)} events its pattern does not match; first "
            f"{sorted(foreign)[:5]!r}"
        )
        assert total >= len(expected[rule]), (
            f"{rule} received {total} messages for {len(expected[rule])} expected events — "
            f"at-least-once permits more, never fewer (min multiplicity {min_multiplicity})"
        )
        assert support <= all_ids, (
            f"{rule} received ids that were never published: {sorted(support - all_ids)[:5]!r}"
        )

    assert len(verdicts["r3"][0]) == N_EVENTS, (
        f"the match-everything rule received {len(verdicts['r3'][0])} of {N_EVENTS} events"
    )
    assert not verdicts["r1"][0] & verdicts["r4"][0], (
        f"prefix 't-000' and anything-but 't-000' both delivered "
        f"{len(verdicts['r1'][0] & verdicts['r4'][0])} events — the two matchers do not "
        f"partition the tenant space"
    )
    assert verdicts["r1"][0] | verdicts["r4"][0] == verdicts["r3"][0], (
        "R1 and R4 together do not cover exactly what R3 received"
    )

    # LOGGED, NOT ASSERTED — EventBridge neither guarantees nor forbids incidental order
    # preservation, so this is measured and reported, never asserted. Asserting it is exactly
    # the mistake this axis exists to prevent.
    r3_first_pass = observed["r3"]
    order_preserved = r3_first_pass == [event_id for event_id, _t, _n in published]

    for rule in PATTERNS:
        shuffled = random.sample(observed[rule], len(observed[rule]))
        assert shuffled != observed[rule], (
            f"shuffling {rule}'s {len(shuffled)} observations produced the identical list; the "
            f"invariance test would be vacuous"
        )
        assert _verdict(shuffled) == verdicts[rule], (
            f"{rule}'s verdict function is NOT shuffle-invariant, so this check depends on the "
            f"order EventBridge delivered in — which EventBridge does not define (observed "
            f"order matched the publish order: {order_preserved})"
        )

if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
