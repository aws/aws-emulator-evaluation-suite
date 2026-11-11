"""log-cwl-plumbing-sixth-subscription-filter-rejected-while-five-deliver."""
from __future__ import annotations

import gzip
import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "log-cwl-plumbing-sixth-subscription-filter-rejected-while-five-deliver"
GROUP = "subscription-delivery"
SERVICES = ["kinesis", "logs"]

_GZIP_MAGIC = b"\x1f\x8b"
# Service Quotas L-87E7D306 "Subscription filters per log group" = 5, Adjustable=False: a fixed
# constant. The PutSubscriptionFilter API documentation says "up to two", but AWS accepts five.
_PER_GROUP_LIMIT = 5


@tags(
    "axis:rejection",
    "cap:c2",
    "concern:data-plane",
    "concern:eventing",
    "concern:negative-classes",
    "dp:api",
    "plane:control",
    "plane:data",
)
def run(ctx) -> None:
    """Five subscription filters on one log group each deliver the same line in their own envelope;
    a sixth is refused with LimitExceededException and gets no log data, and freeing one slot
    lets the identical sixth filter in and deliver (the limit counts attached filters).
    """
    logs = ctx.client("logs")
    kinesis = ctx.client("kinesis")

    ok_stream, refused_stream = (
        ctx.unique_name("sim2real-cwlp-lim-ok-"),
        ctx.unique_name("sim2real-cwlp-lim-no-"),
    )
    ok_arn, refused_arn = _create_kinesis_streams(ctx, kinesis, [ok_stream, refused_stream])
    role_arn = _make_cwl_delivery_role(ctx, [ok_arn, refused_arn])

    group = ctx.unique_name("sim2real-cwlp-lim-lg-")
    logs.create_log_group(logGroupName=group, tags={"sim2real": CHECK})
    ctx.on_cleanup(lambda: logs.delete_log_group(logGroupName=group))
    log_stream = f"{group}-s"
    logs.create_log_stream(logGroupName=group, logStreamName=log_stream)

    accepted = [ctx.unique_name(f"sim2real-cwlp-f{i}-") for i in range(_PER_GROUP_LIMIT)]
    for name in accepted:
        _put_subscription_filter(ctx, logs, group, name, "", ok_arn, role_arn)
    extra = ctx.unique_name("sim2real-cwlp-fx-")

    # --- 1. The filter past the limit is refused with the exact limit error.
    ctx.on_cleanup(lambda: _delete_filter_if_present(logs, group, extra))
    try:
        logs.put_subscription_filter(
            logGroupName=group, filterName=extra, filterPattern="",
            destinationArn=refused_arn, roleArn=role_arn,
        )
        raise AssertionError(
            f"expected subscription filter #{_PER_GROUP_LIMIT + 1} on {group} to be refused, "
            f"but it was accepted"
        )
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        message = exc.response["Error"].get("Message")
    assert code == "LimitExceededException", (
        f"expected LimitExceededException for filter #{_PER_GROUP_LIMIT + 1}, got {code!r} "
        f"({message!r})"
    )
    assert message == "Resource limit exceeded.", (
        f"expected the exact limit message for filter #{_PER_GROUP_LIMIT + 1}, got {message!r}"
    )
    assert _attached(logs, group) == {n: ok_arn for n in accepted}, (
        f"expected exactly the {_PER_GROUP_LIMIT} accepted filters attached, got "
        f"{_attached(logs, group)!r}"
    )

    ok_reader = _ShardReader(kinesis, ok_stream)
    refused_reader = _ShardReader(kinesis, refused_stream)

    # --- 2. Every accepted filter delivers the line, in its own envelope.
    marker = ctx.unique_name("cwlp-lim-")
    line1 = f"{marker} first"
    _write(logs, group, log_stream, line1)
    recs = _poll_until(
        ok_reader,
        lambda rs: _filters_carrying(rs, line1) == set(accepted),
        timeout_s=240.0,
        interval_s=5.0,
        description=f"{line1!r} arrives once per accepted filter on {ok_stream}",
    )
    for r in _data(recs):
        assert r["raw"][:2] == _GZIP_MAGIC, f"non-gzip record {r['raw'][:8]!r}"
        assert len(r["env"]["subscriptionFilters"]) == 1, (
            f"expected each envelope to name exactly one filter, got "
            f"{r['env']['subscriptionFilters']!r}"
        )

    # Differential barrier: a SECOND good-side delivery after the first; then the refused
    # filter's stream must hold no DATA_MESSAGE. It does receive CONTROL_MESSAGE
    # health-check records -- destination validation runs before the limit check -- so only
    # the absence of data is the contract, and control records are not asserted either way.
    line2 = f"{marker} second"
    _write(logs, group, log_stream, line2)
    _poll_until(
        ok_reader,
        lambda rs: _filters_carrying(rs, line2) == set(accepted),
        timeout_s=240.0,
        interval_s=5.0,
        description=f"{line2!r} arrives once per accepted filter on {ok_stream}",
    )
    stray = _data(refused_reader())
    assert stray == [], (
        f"expected the refused filter's destination {refused_stream} to receive no "
        f"DATA_MESSAGE, got {[r['env'] for r in stray]!r}"
    )

    # --- 3. Repair: free one slot; the identical call is accepted and delivery moves.
    freed = accepted[-1]
    logs.delete_subscription_filter(logGroupName=group, filterName=freed)
    _put_subscription_filter(ctx, logs, group, extra, "", refused_arn, role_arn)
    expected_after = {n: ok_arn for n in accepted[:-1]}
    expected_after[extra] = refused_arn
    assert _attached(logs, group) == expected_after, (
        f"expected {expected_after!r} after the repair, got {_attached(logs, group)!r}"
    )
    # A newly attached filter is not live the instant PutSubscriptionFilter returns (a line
    # written immediately after can be lost), so uniquely-marked lines are re-written until
    # one arrives through it.
    line3 = None
    third_attempts: list[str] = []
    recs: list[dict] = []
    deadline = time.monotonic() + 240.0
    while line3 is None and time.monotonic() < deadline:
        attempt = f"{marker} third-{len(third_attempts)}"
        third_attempts.append(attempt)
        _write(logs, group, log_stream, attempt)
        wait_until = time.monotonic() + 20.0
        while line3 is None and time.monotonic() < wait_until:
            time.sleep(5.0)
            recs = refused_reader()
            arrived = [a for a in third_attempts if _filters_carrying(recs, a) == {extra}]
            line3 = arrived[0] if arrived else None
    assert line3 is not None, (
        f"after the repair, none of {third_attempts!r} arrived via {extra!r} on "
        f"{refused_stream}; data lines there: {sorted(_data_lines(recs))!r}"
    )
    leaked = {line1, line2} & _data_lines(recs)
    assert not leaked, f"lines written while {extra!r} was refused leaked: {sorted(leaked)!r}"
    ok_recs = _poll_until(
        ok_reader,
        lambda rs: _filters_carrying(rs, line3) == set(accepted[:-1]),
        timeout_s=240.0,
        interval_s=5.0,
        description=f"{line3!r} arrives once per surviving filter on {ok_stream}",
    )
    assert freed not in _filters_carrying(ok_recs, line3), (
        f"the deleted filter {freed!r} still delivered {line3!r}"
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


class _ShardReader:
    """Accumulate every record on the stream's single shard, carrying the iterator forward."""

    def __init__(self, kinesis, stream_name: str) -> None:
        self._kinesis = kinesis
        shard = kinesis.describe_stream(StreamName=stream_name)["StreamDescription"]["Shards"][0]
        self._iterator = kinesis.get_shard_iterator(
            StreamName=stream_name, ShardId=shard["ShardId"], ShardIteratorType="TRIM_HORIZON"
        )["ShardIterator"]
        self.records: list[dict] = []

    def __call__(self) -> list[dict]:
        for _ in range(5):
            resp = self._kinesis.get_records(ShardIterator=self._iterator, Limit=1000)
            self._iterator = resp["NextShardIterator"]
            for r in resp["Records"]:
                raw = r["Data"]
                self.records.append(
                    {"seq": r["SequenceNumber"], "raw": raw, "env": json.loads(gzip.decompress(raw))}
                )
            if resp.get("MillisBehindLatest", 0) == 0:
                break
        return list(self.records)


def _data(records: list[dict]) -> list[dict]:
    return [r for r in records if r["env"]["messageType"] == "DATA_MESSAGE"]


def _filters_carrying(records: list[dict], line: str) -> set[str]:
    return {
        name
        for r in _data(records)
        if any(e["message"] == line for e in r["env"]["logEvents"])
        for name in r["env"]["subscriptionFilters"]
    }


def _data_lines(records: list[dict]) -> set[str]:
    return {e["message"] for r in _data(records) for e in r["env"]["logEvents"]}


def _attached(logs, group: str) -> dict[str, str]:
    out: dict[str, str] = {}
    kwargs = {"logGroupName": group}
    while True:
        page = logs.describe_subscription_filters(**kwargs)
        for f in page.get("subscriptionFilters", []):
            out[f["filterName"]] = f["destinationArn"]
        if not page.get("nextToken"):
            return out
        kwargs["nextToken"] = page["nextToken"]


def _write(logs, group: str, stream: str, message: str) -> None:
    resp = logs.put_log_events(
        logGroupName=group, logStreamName=stream,
        logEvents=[{"timestamp": _now_ms(), "message": message}],
    )
    assert not resp.get("rejectedLogEventsInfo"), (
        f"expected {message!r} accepted, got {resp.get('rejectedLogEventsInfo')!r}"
    )


def _create_kinesis_streams(ctx, kinesis, names: list[str]) -> list[str]:
    """Create every stream first, then wait for all, so the cost is the max, not the sum."""
    for name in names:
        kinesis.create_stream(StreamName=name, ShardCount=1)
        ctx.on_cleanup(
            lambda n=name: kinesis.delete_stream(StreamName=n, EnforceConsumerDeletion=True)
        )
    arns = []
    for name in names:
        _poll_until(
            lambda n=name: kinesis.describe_stream(StreamName=n)["StreamDescription"]["StreamStatus"],
            lambda s: s == "ACTIVE",
            timeout_s=240.0,
            interval_s=5.0,
            description=f"Kinesis stream {name} becomes ACTIVE",
        )
        kinesis.add_tags_to_stream(StreamName=name, Tags={"sim2real": CHECK})
        arns.append(kinesis.describe_stream(StreamName=name)["StreamDescription"]["StreamARN"])
    return arns


def _make_cwl_delivery_role(ctx, dest_arns: list[str]) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-cwlp-role-")
    policy_name = "cwl-to-kinesis"
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
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]

    def _cleanup() -> None:
        try:
            iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name)
        finally:
            iam.delete_role(RoleName=role_name)

    ctx.on_cleanup(_cleanup)
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName=policy_name,
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": ["kinesis:PutRecord", "kinesis:PutRecords"],
                        "Resource": dest_arns,
                    }
                ],
            }
        ),
    )
    return role_arn


def _delete_filter_if_present(logs, group, filter_name) -> None:
    """Teardown delete that tolerates a filter the check itself already removed."""
    try:
        logs.delete_subscription_filter(logGroupName=group, filterName=filter_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _put_subscription_filter(ctx, logs, group, filter_name, pattern, dest_arn, role_arn) -> None:
    """Retry only while the new role's trust has not propagated (InvalidParameterException)."""

    def _attempt():
        try:
            logs.put_subscription_filter(
                logGroupName=group,
                filterName=filter_name,
                filterPattern=pattern,
                destinationArn=dest_arn,
                roleArn=role_arn,
            )
        except logs.exceptions.InvalidParameterException as exc:
            return str(exc)
        return True

    ctx.on_cleanup(lambda: _delete_filter_if_present(logs, group, filter_name))
    _poll_until(
        _attempt,
        lambda r: r is True,
        timeout_s=180.0,
        interval_s=10.0,
        description=f"PutSubscriptionFilter accepts role {role_arn} once IAM has propagated",
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
