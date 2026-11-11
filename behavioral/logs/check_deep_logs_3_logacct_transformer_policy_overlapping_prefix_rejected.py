"""deep-logs-3-logacct-transformer-policy-overlapping-prefix-rejected."""
from __future__ import annotations

import gzip
import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deep-logs-3-logacct-transformer-policy-overlapping-prefix-rejected"
GROUP = "account-policies"
SERVICES = ["logs"]

_PREFIX = "sim2real-behav-logacct-"
_STREAM = "app"


def _chain(label: str) -> list:
    return [{"parseJSON": {}}, {"addKeys": {"entries": [{"key": "policy", "value": label}]}}]


@tags(
    "axis:rejection",
    "cap:c2",
    "concern:data-plane",
    "concern:negative-classes",
    "dp:api",
    "plane:control", "plane:data", "resource:account-singleton:logs-account-policy",
)
def run(ctx) -> None:
    """A TRANSFORMER_POLICY on a prefix overlapping an existing one is rejected and not persisted;
    a group in the rejected scope is transformed by the first policy alone; a disjoint prefix works.
    """
    logs = ctx.client("logs")
    kinesis = ctx.client("kinesis")

    base = ctx.unique_name(_PREFIX + "xfo-")
    first, second, third = base + "-first", base + "-second", base + "-third"

    logs.put_account_policy(
        policyName=first,
        policyType="TRANSFORMER_POLICY",
        policyDocument=json.dumps(_chain("first")),
        selectionCriteria=f'LogGroupNamePrefix = "{base}"',
    )
    ctx.on_cleanup(
        lambda: logs.delete_account_policy(policyName=first, policyType="TRANSFORMER_POLICY")
    )

    # The overlap rule is stated only in PutAccountPolicy's documentation, not the model.
    try:
        logs.put_account_policy(
            policyName=second,
            policyType="TRANSFORMER_POLICY",
            policyDocument=json.dumps(_chain("second")),
            selectionCriteria=f'LogGroupNamePrefix = "{base}-sub"',
        )
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code")
        message = exc.response.get("Error", {}).get("Message", "")
    else:
        ctx.on_cleanup(
            lambda: logs.delete_account_policy(policyName=second, policyType="TRANSFORMER_POLICY")
        )
        raise AssertionError(
            f"PutAccountPolicy ACCEPTED a TRANSFORMER_POLICY on prefix {base + '-sub'!r}, which "
            f"overlaps the existing policy on {base!r}; real AWS rejects it"
        )
    assert code == "InvalidParameterException", (
        f"expected InvalidParameterException for an overlapping prefix, got {code!r}: {message!r}"
    )
    assert message == "SelectionCriteria prefix is already supported by an existing policy", (
        f"expected the overlapping-prefix refusal, got {message!r}"
    )

    names = _policy_names(logs)
    assert first in names and second not in names, (
        f"after the rejection exactly the first policy must exist among this run's policies; "
        f"DescribeAccountPolicies(TRANSFORMER_POLICY) names {sorted(n for n in names if n.startswith(base))!r}"
    )

    # A group inside the rejected scope is transformed by the first policy only.
    stream, stream_arn, role_arn = _kinesis_sink(ctx, _PREFIX)
    group = base + "-sub-g"
    logs.create_log_group(logGroupName=group, tags={"sim2real": CHECK[:200]})
    ctx.on_cleanup(lambda: logs.delete_log_group(logGroupName=group))
    logs.create_log_stream(logGroupName=group, logStreamName=_STREAM)
    _subscribe_transformed(ctx, logs, group, stream_arn, role_arn, "")
    collector = _Collector(kinesis, stream)

    marker = ctx.unique_name("m-")
    deadline = time.monotonic() + 180.0
    delivered = []
    while not any('"first"' in m for m in delivered):
        assert time.monotonic() < deadline, (
            f"the first policy never transformed {group!r} within 180s; delivered {delivered!r}"
        )
        resp = logs.put_log_events(
            logGroupName=group,
            logStreamName=_STREAM,
            logEvents=[{"timestamp": _now_ms(), "message": json.dumps({"marker": marker})}],
        )
        assert not resp.get("rejectedLogEventsInfo"), f"PutLogEvents rejected: {resp!r}"
        time.sleep(5.0)
        collector()
        delivered = [m for g, m, _ in collector.events if g == group]
    record = json.loads(next(m for m in delivered if '"first"' in m))
    assert record == {"marker": marker, "policy": "first"}, (
        f"{group!r} must be transformed by the first (accepted) policy alone, got {record!r}"
    )
    assert all('"second"' not in m for m in delivered), (
        f"the REJECTED policy's chain reached the ingest path: {delivered!r}"
    )

    # Positive control: a disjoint prefix is accepted.
    put = logs.put_account_policy(
        policyName=third,
        policyType="TRANSFORMER_POLICY",
        policyDocument=json.dumps(_chain("third")),
        selectionCriteria=f'LogGroupNamePrefix = "{base[:-1]}#third"',
    )
    ctx.on_cleanup(
        lambda: logs.delete_account_policy(policyName=third, policyType="TRANSFORMER_POLICY")
    )
    assert put["accountPolicy"]["policyName"] == third, f"PutAccountPolicy echoed {put!r}"
    names = _policy_names(logs)
    assert {first, third} <= names and second not in names, (
        f"expected the first and third policies and not the second; DescribeAccountPolicies "
        f"names {sorted(n for n in names if n.startswith(base))!r}"
    )


def _policy_names(logs) -> set:
    names = set()
    token = None
    while True:
        kwargs = {"policyType": "TRANSFORMER_POLICY"}
        if token is not None:
            kwargs["nextToken"] = token
        page = logs.describe_account_policies(**kwargs)
        names.update(p["policyName"] for p in page.get("accountPolicies", []))
        token = page.get("nextToken")
        if not token:
            return names


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


def _subscribe_transformed(ctx, logs, group, stream_arn, role_arn, pattern):
    """A log-group subscription filter evaluated on -- and delivering -- the TRANSFORMED event."""
    name = ctx.unique_name("sim2real-behav-logacct-sf-")
    _until_role_usable(
        lambda: logs.put_subscription_filter(
            logGroupName=group,
            filterName=name,
            filterPattern=pattern,
            destinationArn=stream_arn,
            roleArn=role_arn,
            applyOnTransformedLogs=True,
        )
    )
    ctx.on_cleanup(lambda: logs.delete_subscription_filter(logGroupName=group, filterName=name))
    return name


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

    def __call__(self):
        resp = self._kinesis.get_records(ShardIterator=self._iterator, Limit=500)
        self._iterator = resp["NextShardIterator"]
        for record in resp["Records"]:
            raw = record["Data"]
            assert raw[:2] == b"\x1f\x8b", f"delivered record is not gzip: {raw[:16]!r}"
            env = json.loads(gzip.decompress(raw))
            if env.get("messageType") != "DATA_MESSAGE":
                continue
            for e in env["logEvents"]:
                self.events.append((env["logGroup"], e["message"], env))
        return list(self.events)


def _stored_messages(logs, group: str, stream: str) -> list[str]:
    out: list[str] = []
    token = None
    while True:
        kwargs = {"logGroupName": group, "logStreamName": stream, "startFromHead": True}
        if token is not None:
            kwargs["nextToken"] = token
        page = logs.get_log_events(**kwargs)
        out.extend(e["message"] for e in page.get("events", []))
        if page.get("nextForwardToken") == token:
            return out
        token = page.get("nextForwardToken")


def _canon(d) -> str:
    return json.dumps(d, sort_keys=True)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
