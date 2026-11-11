"""deep-logs-3-logacct-subscription-filter-policy-not-in-excludes-named-group."""
from __future__ import annotations

import gzip
import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deep-logs-3-logacct-subscription-filter-policy-not-in-excludes-named-group"
GROUP = "account-policies"
SERVICES = ["logs"]

_PREFIX = "sim2real-behav-logacct-"
_STREAM = "app"


@tags("axis:happy-path", "concern:data-plane", "concern:eventing", "dp:api", "plane:data", "cap:c2", "resource:account-singleton:logs-account-policy")
def run(ctx) -> None:
    """An account SUBSCRIPTION_FILTER_POLICY with `LogGroupName NOT IN ["<excluded>"]` delivers the other
    group's events to Kinesis in an envelope naming the policy, while the excluded group delivers nothing;
    re-putting the policy with a different exclusion makes that group deliver.
    """
    logs = ctx.client("logs")
    kinesis = ctx.client("kinesis")
    account = ctx.client("sts").get_caller_identity()["Account"]

    stream, stream_arn, role_arn = _kinesis_sink(ctx, _PREFIX)

    included = ctx.unique_name(_PREFIX + "sfin-")
    excluded = ctx.unique_name(_PREFIX + "sfex-")
    for g in (included, excluded):
        logs.create_log_group(logGroupName=g, tags={"sim2real": CHECK})
        ctx.on_cleanup(lambda _g=g: logs.delete_log_group(logGroupName=_g))
        logs.create_log_stream(logGroupName=g, logStreamName=_STREAM)

    token = "SIM2REALACCTSF" + ctx.unique_name("").upper()
    policy = ctx.unique_name(_PREFIX + "sfp-")
    document = json.dumps(
        {
            "DestinationArn": stream_arn,
            "RoleArn": role_arn,
            "FilterPattern": token,
            "Distribution": "Random",
        }
    )
    put = _until_role_usable(
        lambda: logs.put_account_policy(
            policyName=policy,
            policyType="SUBSCRIPTION_FILTER_POLICY",
            policyDocument=document,
            selectionCriteria=f'LogGroupName NOT IN ["{excluded}"]',
        )
    )

    def _delete_policy() -> None:
        try:
            logs.delete_account_policy(policyName=policy, policyType="SUBSCRIPTION_FILTER_POLICY")
        except logs.exceptions.ResourceNotFoundException:
            pass

    ctx.on_cleanup(_delete_policy)
    echoed = put["accountPolicy"]
    assert echoed["selectionCriteria"] == f'LogGroupName NOT IN ["{excluded}"]', (
        f"PutAccountPolicy echoed selectionCriteria {echoed.get('selectionCriteria')!r}"
    )

    collector = _Collector(kinesis, stream)
    rounds = {"n": 0}

    def _write_round(phase: str) -> int:
        rounds["n"] += 1
        n = rounds["n"]
        for g in (included, excluded):
            resp = logs.put_log_events(
                logGroupName=g,
                logStreamName=_STREAM,
                logEvents=[{"timestamp": _now_ms(), "message": f"{token} {phase} r{n} {g}"}],
            )
            assert not resp.get("rejectedLogEventsInfo"), (
                f"PutLogEvents rejected the round-{n} event on {g!r}: {resp!r}"
            )
        return n

    def _from(group: str):
        return [m for g, m, _ in collector.events if g == group]

    # --- 1. The included group delivers; L is its measured latency on this wiring.
    started = time.monotonic()
    deadline = started + 180.0
    while not _from(included):
        assert time.monotonic() < deadline, (
            f"the account subscription policy never forwarded {included!r} (not named in NOT IN) "
            f"to {stream!r} within 180s; delivered so far {collector.events!r}"
        )
        _write_round("excl")
        time.sleep(4.0)
        collector()
    latency_s = time.monotonic() - started

    # --- 2. Hold: the included side keeps delivering, the excluded side stays silent.
    hold_s = min(max(3.0 * latency_s, 15.0), 90.0)
    baseline = len(_from(included))
    hold_end = time.monotonic() + hold_s
    while time.monotonic() < hold_end:
        _write_round("excl")
        time.sleep(4.0)
        collector()
        assert not _from(excluded), (
            f"{excluded!r} is named in the policy's NOT IN list yet its events reached the "
            f"stream: {_from(excluded)!r} (included group latency was {latency_s:.1f}s)"
        )
    collector()
    assert len(_from(included)) >= baseline + 3, (
        f"the included group stopped delivering during the {hold_s:.0f}s hold: "
        f"{len(_from(included))} events vs {baseline} at its start -- the barrier is void"
    )
    assert not _from(excluded), f"excluded group delivered at end of hold: {_from(excluded)!r}"
    last_excl_round = rounds["n"]

    # --- 3. Every delivered envelope is the CWL gzip envelope, attributed to the POLICY.
    for env in collector.envelopes:
        assert env["owner"] == account, f"envelope owner {env['owner']!r}, expected {account!r}"
        assert env["logGroup"] == included, f"unexpected logGroup in envelope: {env!r}"
        assert env["logStream"] == _STREAM, f"envelope logStream {env['logStream']!r}"
        assert env["subscriptionFilters"] == [policy], (
            f"an account-policy delivery must name the policy {policy!r} as its filter, got "
            f"{env['subscriptionFilters']!r}"
        )
        for e in env["logEvents"]:
            assert e["message"].startswith(f"{token} excl r"), f"unexpected event {e!r}"
    group_filters = logs.describe_subscription_filters(logGroupName=included)[
        "subscriptionFilters"
    ]
    assert group_filters == [], (
        "the account policy must not be materialised as a log-group subscription filter; "
        f"DescribeSubscriptionFilters on {included!r} returned {group_filters!r}"
    )

    # --- 4. Repair the one difference: point the exclusion at a name no group has.
    logs.put_account_policy(
        policyName=policy,
        policyType="SUBSCRIPTION_FILTER_POLICY",
        policyDocument=document,
        selectionCriteria=f'LogGroupName NOT IN ["{excluded}-unused"]',
    )
    repair_deadline = time.monotonic() + 180.0
    while not any(" repair " in m for m in _from(excluded)):
        assert time.monotonic() < repair_deadline, (
            f"after re-putting the policy without {excluded!r} in NOT IN, that group still did "
            f"not deliver within 180s -- the stream may never have been reachable for it"
        )
        _write_round("repair")
        time.sleep(5.0)
        collector()
    pre_repair = [m for m in _from(excluded) if " excl " in m]
    assert pre_repair == [], (
        f"events written to {excluded!r} while it was excluded were delivered after the repair "
        f"(rounds <= {last_excl_round}): {pre_repair!r}"
    )


def _now_ms() -> int:
    return int(time.time() * 1000)


def _poll_until(probe, predicate, *, timeout_s, interval_s, description):
    """Poll probe() until predicate() holds; RAISE on the deadline (never return last)."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _until_role_usable(call):
    """Retry ``call`` while CloudWatch Logs reports it cannot yet deliver its test message to
    the destination -- the observable symptom of the new role not having propagated. Any
    other error is raised at once."""
    deadline = time.monotonic() + 180.0
    while True:
        try:
            return call()
        except ClientError as exc:
            err = exc.response.get("Error", {})
            if (
                err.get("Code") != "InvalidParameterException"
                or "test message" not in err.get("Message", "")
                or time.monotonic() > deadline
            ):
                raise
        time.sleep(2)  # IAM propagation exposes no condition; the retry above is the gate


def _kinesis_sink(ctx, prefix):
    """A 1-shard Kinesis stream plus a role CloudWatch Logs can assume to write to it."""
    kinesis = ctx.client("kinesis")
    iam = ctx.client("iam")
    stream = ctx.unique_name(prefix + "ks-")
    kinesis.create_stream(StreamName=stream, ShardCount=1, Tags={"sim2real": CHECK[:200]})
    ctx.on_cleanup(lambda: kinesis.delete_stream(StreamName=stream, EnforceConsumerDeletion=True))
    role = ctx.unique_name(prefix + "role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "logs.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role_arn = iam.create_role(
        RoleName=role,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK[:200]}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role))
    _poll_until(
        lambda: kinesis.describe_stream(StreamName=stream)["StreamDescription"]["StreamStatus"],
        lambda s: s == "ACTIVE",
        timeout_s=180.0,
        interval_s=3.0,
        description=f"Kinesis stream {stream} becomes ACTIVE",
    )
    stream_arn = kinesis.describe_stream(StreamName=stream)["StreamDescription"]["StreamARN"]
    iam.put_role_policy(
        RoleName=role,
        PolicyName="cwl-to-kinesis",
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": ["kinesis:PutRecord", "kinesis:PutRecords"],
                        "Resource": stream_arn,
                    }
                ],
            }
        ),
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role, PolicyName="cwl-to-kinesis"))
    return stream, stream_arn, role_arn


class _Collector:
    """Accumulate every DATA_MESSAGE event delivered to the stream as (logGroup, message,
    envelope). The shard iterator is carried forward across polls, never restarted."""

    def __init__(self, kinesis, stream: str) -> None:
        shard = kinesis.describe_stream(StreamName=stream)["StreamDescription"]["Shards"][0][
            "ShardId"
        ]
        self._kinesis = kinesis
        self._iterator = kinesis.get_shard_iterator(
            StreamName=stream, ShardId=shard, ShardIteratorType="TRIM_HORIZON"
        )["ShardIterator"]
        self.events: list[tuple[str, str, dict]] = []
        self.envelopes: list[dict] = []

    def __call__(self):
        resp = self._kinesis.get_records(ShardIterator=self._iterator, Limit=500)
        self._iterator = resp["NextShardIterator"]
        for record in resp["Records"]:
            raw = record["Data"]
            assert raw[:2] == b"\x1f\x8b", f"delivered record is not gzip: {raw[:16]!r}"
            env = json.loads(gzip.decompress(raw))
            if env.get("messageType") != "DATA_MESSAGE":
                continue
            self.envelopes.append(env)
            for e in env["logEvents"]:
                self.events.append((env["logGroup"], e["message"], env))
        return list(self.events)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
