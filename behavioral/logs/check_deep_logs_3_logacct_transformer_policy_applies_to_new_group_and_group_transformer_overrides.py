"""deep-logs-3-logacct-transformer-policy-applies-to-new-group-and-group-transformer-overrides."""
from __future__ import annotations

import gzip
import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deep-logs-3-logacct-transformer-policy-applies-to-new-group-and-group-transformer-overrides"
GROUP = "account-policies"
SERVICES = ["logs"]

_PREFIX = "sim2real-behav-logacct-"
_STREAM = "app"


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data", "resource:account-singleton:logs-account-policy")
def run(ctx) -> None:
    """A prefix-scoped account TRANSFORMER_POLICY transforms a new in-prefix group with no transformer;
    an in-prefix group's own transformer replaces (not merges) it; an out-of-prefix group is untouched.

    Reference: https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/CloudWatch-Logs-Transformation.html
    """
    logs = ctx.client("logs")
    kinesis = ctx.client("kinesis")

    # A unique prefix so this policy cannot overlap another transformer policy in the account.
    prefix = ctx.unique_name(_PREFIX + "xfp-")
    policy = prefix + "-policy"
    account_chain = [
        {"parseJSON": {}},
        {
            "addKeys": {
                "entries": [
                    {"key": "applied_by", "value": "account"},
                    {"key": "acct_only", "value": "yes"},
                ]
            }
        },
    ]
    group_chain = [
        {"parseJSON": {}},
        {"addKeys": {"entries": [{"key": "applied_by", "value": "group"}]}},
    ]
    put = logs.put_account_policy(
        policyName=policy,
        policyType="TRANSFORMER_POLICY",
        policyDocument=json.dumps(account_chain),
        selectionCriteria=f'LogGroupNamePrefix = "{prefix}"',
    )
    ctx.on_cleanup(
        lambda: logs.delete_account_policy(policyName=policy, policyType="TRANSFORMER_POLICY")
    )
    assert put["accountPolicy"]["selectionCriteria"] == f'LogGroupNamePrefix = "{prefix}"', (
        f"PutAccountPolicy echoed {put['accountPolicy']!r}"
    )

    stream, stream_arn, role_arn = _kinesis_sink(ctx, _PREFIX)

    # All three groups are created AFTER the account policy exists.
    governed = prefix + "-acct"
    own = prefix + "-own"
    outside = ctx.unique_name(_PREFIX + "xfout-")
    for g in (governed, own, outside):
        logs.create_log_group(logGroupName=g, tags={"sim2real": CHECK[:200]})
        ctx.on_cleanup(lambda _g=g: logs.delete_log_group(logGroupName=_g))
        logs.create_log_stream(logGroupName=g, logStreamName=_STREAM)

    logs.put_transformer(logGroupIdentifier=own, transformerConfig=group_chain)
    ctx.on_cleanup(lambda: logs.delete_transformer(logGroupIdentifier=own))

    inherited = logs.get_transformer(logGroupIdentifier=governed).get("transformerConfig", [])
    assert inherited == [], (
        f"{governed!r} was never given a log-group transformer, so GetTransformer must report "
        f"none; got {inherited!r}"
    )

    for g in (governed, own, outside):
        _subscribe_transformed(ctx, logs, g, stream_arn, role_arn, "")
    collector = _Collector(kinesis, stream)

    marker = ctx.unique_name("r-")
    rounds = {"n": 0}

    def _write_round() -> None:
        rounds["n"] += 1
        for g in (governed, own, outside):
            body = json.dumps({"marker": marker, "n": rounds["n"], "src": g[-4:]})
            resp = logs.put_log_events(
                logGroupName=g,
                logStreamName=_STREAM,
                logEvents=[{"timestamp": _now_ms(), "message": body}],
            )
            assert not resp.get("rejectedLogEventsInfo"), f"rejected on {g!r}: {resp!r}"

    def _latest(group: str):
        msgs = [m for g, m, _ in collector.events if g == group]
        return msgs[-1] if msgs else None

    # Wait (bounded) until one round has been delivered from all three groups and the
    # governed group's delivery carries the account chain -- the policy's propagation to a
    # brand-new group is the observable condition. GetTransformer on the governed group returns
    # an empty chain, so only the delivered data reveals the inheritance.
    deadline = time.monotonic() + 180.0
    while True:
        _write_round()
        time.sleep(5.0)
        collector()
        latest = {g: _latest(g) for g in (governed, own, outside)}
        if all(v is not None for v in latest.values()) and '"account"' in latest[governed]:
            break
        assert time.monotonic() < deadline, (
            f"within 180s the three groups did not all deliver with the account transformer "
            f"applied to {governed!r}; latest deliveries {latest!r}"
        )

    governed_rec = json.loads(latest[governed])
    assert governed_rec["applied_by"] == "account" and governed_rec["acct_only"] == "yes", (
        f"the account TRANSFORMER_POLICY must transform {governed!r} (in prefix, created after "
        f"the policy, no own transformer); delivered {governed_rec!r}"
    )
    assert governed_rec["marker"] == marker and governed_rec["src"] == governed[-4:], (
        f"the account chain must keep the parsed source fields: {governed_rec!r}"
    )

    own_rec = json.loads(latest[own])
    assert own_rec["applied_by"] == "group", (
        f"a log-group transformer must take precedence over the account policy for {own!r}; "
        f"delivered {own_rec!r}"
    )
    assert "acct_only" not in own_rec, (
        f"the account chain must be IGNORED, not merged, for a group with its own transformer: "
        f"{own_rec!r} carries the account-only key"
    )
    assert own_rec["marker"] == marker, f"group chain lost the parsed source fields: {own_rec!r}"

    # AWS delivers an empty message for the untransformed group; only the absent keys are asserted.
    out_msg = latest[outside]
    assert "applied_by" not in out_msg and "acct_only" not in out_msg, (
        f"{outside!r} is outside the policy prefix {prefix!r}, yet its delivery carries the "
        f"account chain's keys: {out_msg!r}"
    )

    # Every delivery from the two in-prefix groups is consistent with its own rule.
    for g, m, _ in collector.events:
        if g == own:
            assert "acct_only" not in m, f"account chain leaked onto {own!r}: {m!r}"
        if g == outside:
            assert "acct_only" not in m, f"account chain leaked onto {outside!r}: {m!r}"


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
