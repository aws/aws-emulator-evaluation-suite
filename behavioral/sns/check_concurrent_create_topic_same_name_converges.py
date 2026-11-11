"""concurrent-create-topic-same-name-converges."""
from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor

from behavioral_harness import tags

CHECK = "concurrent-create-topic-same-name-converges"
GROUP = 'topic-lifecycle'
SERVICES = ['sns']

_CALLERS = 10


def _poll(fn, pred, *, timeout_s, interval_s, what):
    """Poll fn() until pred(val); raise AssertionError on deadline miss (never a bare sleep)."""
    deadline = time.monotonic() + timeout_s
    val = fn()
    while not pred(val):
        if time.monotonic() >= deadline:
            raise AssertionError(f"{what}: condition not met within {timeout_s}s, last value {val!r}")
        time.sleep(interval_s)
        val = fn()
    return val


@tags("axis:happy-path", "cap:c2", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Ten concurrent CreateTopic calls for one new name, all with identical attributes, all
    succeed with the same TopicArn and leave exactly one topic of that name behind.
    """
    sns = ctx.client("sns")
    name = ctx.unique_name("sim2real-behav-sns-ccreate-")
    attrs = {"DisplayName": "race"}
    # Topic ARNs are a pure function of partition, region, account and name, and DeleteTopic
    # is idempotent, so the net is registered before the racers can create anything.
    expected_arn = f"arn:aws:sns:{ctx.region}:{ctx.account}:{name}"
    ctx.on_cleanup(lambda: sns.delete_topic(TopicArn=expected_arn))

    def _create():
        return sns.create_topic(Name=name, Attributes=attrs)["TopicArn"]

    with ThreadPoolExecutor(max_workers=_CALLERS) as pool:
        futures = [pool.submit(_create) for _ in range(_CALLERS)]
        arns = [f.result() for f in futures]
    arn = arns[0]
    assert set(arns) == {arn}, f"concurrent creators got {len(set(arns))} distinct TopicArns"
    assert arn == expected_arn, "the TopicArn must be the deterministic ARN for this name"
    assert arn.rsplit(":", 1)[-1] == name, "the TopicArn's last segment must be the requested name"

    def _named():
        return [t["TopicArn"] for p in sns.get_paginator("list_topics").paginate()
                for t in p["Topics"] if t["TopicArn"].rsplit(":", 1)[-1] == name]

    named = _poll(_named, lambda v: len(v) >= 1, timeout_s=60.0, interval_s=3.0,
                  what="the raced topic appears in ListTopics")
    assert named == [arn], f"exactly one topic of the raced name must exist, got {len(named)}"
    display = sns.get_topic_attributes(TopicArn=arn)["Attributes"].get("DisplayName")
    assert display == "race", f"the converged topic must carry the requested DisplayName, got {display!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
