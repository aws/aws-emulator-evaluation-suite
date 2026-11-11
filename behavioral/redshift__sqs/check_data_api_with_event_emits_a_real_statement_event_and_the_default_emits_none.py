"""data-api-with-event-emits-a-real-statement-event-and-the-default-emits-none."""

from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "data-api-with-event-emits-a-real-statement-event-and-the-default-emits-none"
GROUP = "event-propagation"
SERVICES = ["redshift", "sqs"]


_THROTTLE = (
    "Throttling",
    "ThrottlingException",
    "RequestLimitExceeded",
    "TooManyRequestsException",
    "SlowDown",
)

DATAPLANE_MARKER = "DATAPLANE_UNIMPLEMENTED"

NODE_TYPE_PREFERENCE = ("dc2.large", "ra3.large", "ra3.xlplus")
MASTER_USERNAME = "adminuser"
MASTER_PASSWORD = "TestPassw0rd123"
DB_NAME = "devdb"
_NOT_FOUND_CLUSTER = ("ClusterNotFound", "ClusterNotFoundFault")
_INVALID_STATE = ("InvalidClusterState", "InvalidClusterStateFault")
_CLUSTER_DEADLINE_S = 900
_DELETE_CLUSTER_DEADLINE_S = 300
_TERMINAL_STATEMENT = ("FINISHED", "FAILED", "ABORTED")
_STATEMENT_DEADLINE_S = 420
_WARM_STATEMENT_DEADLINE_S = 120

_EVENT_SOURCE = "aws.redshift-data"
_EVENT_DETAIL_TYPE = "Redshift Data Statement Status Change"
# The positive is retried to absorb EventBridge rule propagation; the absence never is.
_POSITIVE_WAIT_S = 240
_POSITIVE_ATTEMPTS = 3


def _code_of(exc):
    if isinstance(exc, ClientError):
        return exc.response["Error"]["Code"]
    return f"EXC:{type(exc).__name__}"


def _retrying(fn, attempts=6, delay_s=5.0):
    """Call *fn*, retrying only on API throttling (a rate limit is infrastructure noise under
    parallel runs, not a behavioral observation)."""
    last = None
    for attempt in range(attempts):
        try:
            return fn()
        except ClientError as exc:
            if _code_of(exc) not in _THROTTLE:
                raise
            last = exc
            time.sleep(delay_s * (attempt + 1))
    raise last


def _capped(ctx, timeout_s):
    """*timeout_s*, capped by the run's remaining time so a wait fails with its own message."""
    left = ctx.time_left()
    return timeout_s if left is None else max(1.0, min(timeout_s, left - 10.0))


def _wait_until(ctx, probe, done, timeout_s, interval_s, what="condition"):
    """Poll *probe* until *done*. RAISES on timeout, never returns its last value."""
    timeout_s = _capped(ctx, timeout_s)
    deadline = time.monotonic() + timeout_s
    while True:
        observed = probe()
        if done(observed):
            return observed
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"timed out after {timeout_s:.0f}s waiting for {what}; last observed={observed!r}"
            )
        time.sleep(interval_s)


def _node_type(rs, cluster_type="single-node"):
    """Cheapest orderable node type for *cluster_type* in this region, read off the account."""
    available = []
    marker = None
    while True:
        kwargs = {"MaxRecords": 100}
        if marker:
            kwargs["Marker"] = marker
        resp = _retrying(lambda: rs.describe_orderable_cluster_options(**kwargs))
        for opt in resp.get("OrderableClusterOptions", []):
            if opt.get("ClusterType") != cluster_type:
                continue
            nt = opt.get("NodeType")
            if nt and nt not in available:
                available.append(nt)
        marker = resp.get("Marker")
        if not marker:
            break
    chosen = next((nt for nt in NODE_TYPE_PREFERENCE if nt in available), None)
    if chosen is None:
        if not available:
            raise AssertionError(
                f"no orderable {cluster_type} options in {rs.meta.region_name}; "
                f"DescribeOrderableClusterOptions returned nothing usable"
            )
        chosen = sorted(available)[0]
    return chosen


def _cluster_params(rs, cluster_id, **overrides):
    """Cheapest shape that still proves the invariant: ONE node, not publicly accessible, 1-day
    snapshot retention (RA3 refuses 0)."""
    params = dict(
        ClusterIdentifier=cluster_id,
        NodeType=_node_type(rs),
        MasterUsername=MASTER_USERNAME,
        MasterUserPassword=MASTER_PASSWORD,
        ClusterType="single-node",
        DBName=DB_NAME,
        PubliclyAccessible=False,
        Encrypted=True,
        AutomatedSnapshotRetentionPeriod=1,
    )
    params.update(overrides)
    return params


def _create_cluster(ctx, rs, cluster_id, **overrides):
    """CreateCluster with a bounded retry on the association races."""
    deadline = time.monotonic() + _capped(ctx, 180)
    while True:
        try:
            return _retrying(
                lambda: rs.create_cluster(**_cluster_params(rs, cluster_id, **overrides))
            )
        except ClientError as exc:
            if (
                _code_of(exc) not in _INVALID_STATE + ("InvalidIamRoleFault",)
                or time.monotonic() >= deadline
            ):
                raise
            time.sleep(2)


def _cluster_status(rs, cluster_id):
    try:
        resp = _retrying(lambda: rs.describe_clusters(ClusterIdentifier=cluster_id))
    except ClientError as exc:
        if _code_of(exc) in _NOT_FOUND_CLUSTER:
            return None
        raise
    clusters = resp.get("Clusters", [])
    return clusters[0]["ClusterStatus"] if clusters else None


def _wait_for_cluster_available(ctx, rs, cluster_id, timeout_s=_CLUSTER_DEADLINE_S):
    terminal = {
        "available",
        "incompatible-network",
        "incompatible-parameters",
        "incompatible-hsm",
        "insufficient-capacity",
        "hardware-failure",
        None,
    }
    status = _wait_until(
        ctx,
        lambda: _cluster_status(rs, cluster_id),
        lambda s: s in terminal,
        timeout_s=timeout_s,
        interval_s=2,
        what=f"cluster {cluster_id} to reach a terminal creation state",
    )
    assert status == "available", (
        f"cluster {cluster_id} reached terminal state {status!r}, expected 'available'"
    )
    return status


def _delete_cluster(rs, cluster_id):
    """Cost-leak teardown. Anything OTHER than not-found / wrong-state / throttle RAISES."""
    deadline = time.monotonic() + _DELETE_CLUSTER_DEADLINE_S
    while True:
        try:
            rs.delete_cluster(ClusterIdentifier=cluster_id, SkipFinalClusterSnapshot=True)
            return
        except ClientError as exc:
            code = _code_of(exc)
            if code in _NOT_FOUND_CLUSTER:
                return
            if code not in _INVALID_STATE + _THROTTLE or time.monotonic() >= deadline:
                raise
        time.sleep(20)


def _wait_statement(ctx, rsd, statement_id, timeout_s=_STATEMENT_DEADLINE_S):
    return _wait_until(
        ctx,
        lambda: _retrying(lambda: rsd.describe_statement(Id=statement_id)),
        lambda d: d.get("Status") in _TERMINAL_STATEMENT,
        timeout_s=timeout_s,
        interval_s=2,
        what=f"statement {statement_id} to reach a terminal status",
    )


def _submit(rsd, cluster_id, sql, **kwargs):
    return _retrying(
        lambda: rsd.execute_statement(
            ClusterIdentifier=cluster_id, Database=DB_NAME, DbUser=MASTER_USERNAME, Sql=sql,
            **kwargs,
        )
    )


def _run_sql(ctx, rsd, cluster_id, sql, timeout_s=_STATEMENT_DEADLINE_S, **kwargs):
    """Submit *sql*, wait for terminal, assert it FINISHED. Returns the ExecuteStatement Id."""
    statement_id = _submit(rsd, cluster_id, sql, **kwargs)["Id"]
    described = _wait_statement(ctx, rsd, statement_id, timeout_s=timeout_s)
    assert described["Status"] == "FINISHED", (
        f"{DATAPLANE_MARKER}: SQL {sql!r} did not FINISH: status={described['Status']!r} "
        f"error={described.get('Error')!r}"
    )
    return statement_id


def _drain(ctx, sqs, queue_url, seen, timeout_s, until):
    """Receive and delete messages until statement *until* is in *seen* (or *timeout_s* passes),
    collecting EventBridge envelopes into *seen* keyed by detail.statementId."""
    deadline = time.monotonic() + _capped(ctx, timeout_s)
    while until not in seen and time.monotonic() < deadline:
        resp = _retrying(
            lambda: sqs.receive_message(
                QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=20
            )
        )
        for message in resp.get("Messages", []):
            _retrying(
                lambda m=message: sqs.delete_message(
                    QueueUrl=queue_url, ReceiptHandle=m["ReceiptHandle"]
                )
            )
            try:
                envelope = json.loads(message["Body"])
            except ValueError as exc:
                raise AssertionError(
                    f"every message on this queue is an EventBridge envelope and must parse as "
                    f"JSON; got {message['Body']!r} ({exc})"
                ) from exc
            key = (envelope.get("detail") or {}).get("statementId")
            seen[key] = envelope
    return seen


@tags(
    "axis:negative-delivery",
    "cap:c4",
    "concern:data-plane",
    "concern:eventing",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """A Data API statement with WithEvent=True delivers an aws.redshift-data status-change event
    naming its statement and cluster to SQS; a twin submitted without WithEvent delivers none, even
    once a later WithEvent=True statement's event has arrived on the same queue.

    Reference: https://docs.aws.amazon.com/redshift-data/latest/APIReference/API_ExecuteStatement.html
    """
    rs = ctx.client("redshift")
    rsd = ctx.client("redshift-data")
    sqs = ctx.client("sqs")
    events = ctx.client("events")

    account = ctx.client("sts").get_caller_identity()["Account"]
    assert account and account.isdigit(), (
        f"STS must report a numeric account id for the test account, got {account!r}"
    )
    scenario = "rs-withevent"
    tag_set = {"sim2real": scenario}

    queue_name = ctx.unique_name("sim2real-behav-rs-withevent-")
    queue_url = _retrying(
        lambda: sqs.create_queue(QueueName=queue_name, tags=tag_set)
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=queue_url))
    queue_arn = _retrying(
        lambda: sqs.get_queue_attributes(QueueUrl=queue_url, AttributeNames=["QueueArn"])
    )["Attributes"]["QueueArn"]

    # The pattern matches on SOURCE and DETAIL-TYPE only. No filter on the statement id, so a
    # target that emits an event for the WithEvent-less statement CANNOT escape by failing to match
    # — the negative below is an absence at the destination, not a pattern miss.
    rule_name = ctx.unique_name("sim2real-behav-rs-withevent-rule-")
    rule_arn = _retrying(
        lambda: events.put_rule(
            Name=rule_name,
            EventPattern=json.dumps(
                {"source": [_EVENT_SOURCE], "detail-type": [_EVENT_DETAIL_TYPE]}
            ),
            State="ENABLED",
            Tags=[{"Key": k, "Value": v} for k, v in tag_set.items()],
        )
    )["RuleArn"]

    def _cleanup_rule():
        try:
            events.remove_targets(Rule=rule_name, Ids=["1"])
        except ClientError as exc:
            if _code_of(exc) != "ResourceNotFoundException":
                raise
        try:
            events.delete_rule(Name=rule_name)
        except ClientError as exc:
            if _code_of(exc) != "ResourceNotFoundException":
                raise

    ctx.on_cleanup(_cleanup_rule)

    _retrying(
        lambda: sqs.set_queue_attributes(
            QueueUrl=queue_url,
            Attributes={
                "Policy": json.dumps(
                    {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Sid": "AllowEventBridgeSend",
                                "Effect": "Allow",
                                "Principal": {"Service": "events.amazonaws.com"},
                                "Action": "sqs:SendMessage",
                                "Resource": queue_arn,
                                "Condition": {"ArnEquals": {"aws:SourceArn": rule_arn}},
                            }
                        ],
                    }
                )
            },
        )
    )
    _retrying(lambda: events.put_targets(Rule=rule_name, Targets=[{"Id": "1", "Arn": queue_arn}]))

    # The wiring is created FIRST so cluster provisioning doubles as the propagation window.
    cluster_id = ctx.unique_name("sim2real-behav-rs-wev-cluster-")
    # Registered before the cluster exists: a leaked provisioned cluster is costly.
    ctx.on_cleanup(lambda: _delete_cluster(rs, cluster_id))
    _create_cluster(ctx, rs, cluster_id, Tags=[{"Key": "sim2real", "Value": scenario}])
    _wait_for_cluster_available(ctx, rs, cluster_id)
    cluster_arn = f"arn:aws:redshift:{ctx.region}:{account}:cluster:{cluster_id}"

    # Absorbs connection establishment, so the two timed statements below are on a warm path.
    _run_sql(ctx, rsd, cluster_id, "SELECT 1")

    delivered = None
    quiet_id = None
    for attempt in range(_POSITIVE_ATTEMPTS):
        # The twin: same cluster, same database, same user, same SQL, submitted seconds apart. The
        # ONLY difference is WithEvent.
        loud_id = _submit(
            rsd,
            cluster_id,
            "SELECT 1",
            WithEvent=True,
            StatementName=f"sim2real-behav-loud-{attempt}",
        )["Id"]
        quiet_id = _submit(
            rsd,
            cluster_id,
            "SELECT 1",
            StatementName=f"sim2real-behav-quiet-{attempt}",
        )["Id"]
        assert quiet_id != loud_id, (
            f"the two statements of the twin must be distinct: both are {loud_id!r}"
        )
        loud_final = _wait_statement(ctx, rsd, loud_id, timeout_s=_WARM_STATEMENT_DEADLINE_S)
        quiet_final = _wait_statement(ctx, rsd, quiet_id, timeout_s=_WARM_STATEMENT_DEADLINE_S)
        assert loud_final["Status"] == "FINISHED", (
            f"{DATAPLANE_MARKER}: the WithEvent=True statement must FINISH before any event can "
            f"be expected, got {loud_final['Status']!r} error={loud_final.get('Error')!r}"
        )
        assert quiet_final["Status"] == "FINISHED", (
            f"{DATAPLANE_MARKER}: the twin without WithEvent must FINISH too — an event-free "
            f"statement that FAILED would make the absence meaningless — got "
            f"{quiet_final['Status']!r} error={quiet_final.get('Error')!r}"
        )

        seen = {}
        _drain(ctx, sqs, queue_url, seen, timeout_s=_POSITIVE_WAIT_S, until=loud_id)
        if loud_id in seen:
            delivered = seen
            break

    assert delivered is not None, (
        f"a statement submitted with WithEvent=True must publish an {_EVENT_SOURCE!r} "
        f"{_EVENT_DETAIL_TYPE!r} event that the rule forwards to SQS; nothing arrived in "
        f"{_POSITIVE_ATTEMPTS} windows of {_POSITIVE_WAIT_S}s each. Without this positive the "
        f"absence below would prove nothing"
    )

    # ---- the delivered event is the one this check caused, with the right shape ----
    envelope = delivered[loud_id]
    assert envelope.get("source") == _EVENT_SOURCE, (
        f"the event's source must be {_EVENT_SOURCE!r}, got {envelope.get('source')!r}"
    )
    assert envelope.get("detail-type") == _EVENT_DETAIL_TYPE, (
        f"the event's detail-type must be {_EVENT_DETAIL_TYPE!r}, got "
        f"{envelope.get('detail-type')!r}"
    )
    assert envelope.get("account") == account, (
        f"the event must be attributed to the calling account {account!r}, got "
        f"{envelope.get('account')!r}"
    )
    assert envelope.get("region") == ctx.region, (
        f"the event must be attributed to {ctx.region!r}, got {envelope.get('region')!r}"
    )
    assert cluster_arn in (envelope.get("resources") or []), (
        f"the event's resources must name the cluster the statement ran on, {cluster_arn!r}; got "
        f"{envelope.get('resources')!r}"
    )
    detail = envelope.get("detail") or {}
    assert detail.get("statementId") == loud_id, (
        f"the event's detail.statementId must be the ExecuteStatement Id {loud_id!r}, got "
        f"{detail.get('statementId')!r}"
    )
    assert detail.get("state") == "FINISHED", (
        f"the event's detail.state must be the terminal status the statement reached, 'FINISHED'; "
        f"got {detail.get('state')!r}"
    )

    # ---- the absence, on the same wiring, in the same window that delivered the positive ----
    assert quiet_id not in delivered, (
        f"the twin submitted WITHOUT WithEvent must publish NOTHING: an event for {quiet_id!r} "
        f"arrived on the same rule and queue that delivered {loud_id!r}. WithEvent defaults to "
        f"false, so a target that emits unconditionally is over-delivering"
    )

    # ---- repair only the withheld thing: WithEvent=True again, and delivery resumes ----
    # Its event, submitted after the twin, is the contrast that bounds the twin's absence.
    repaired_id = _run_sql(
        ctx,
        rsd,
        cluster_id,
        "SELECT 1",
        timeout_s=_WARM_STATEMENT_DEADLINE_S,
        WithEvent=True,
        StatementName="sim2real-behav-repaired",
    )
    resumed = {}
    _drain(ctx, sqs, queue_url, resumed, timeout_s=_POSITIVE_WAIT_S, until=repaired_id)
    assert repaired_id in resumed, (
        f"turning WithEvent back on must restore delivery on the SAME wiring — that is what makes "
        f"the twin's silence evidence about WithEvent and not about the queue; nothing "
        f"arrived for {repaired_id!r} within {_POSITIVE_WAIT_S}s"
    )
    assert quiet_id not in resumed, (
        f"the WithEvent-less statement's event must still be absent once the later WithEvent=True "
        f"statement's event has arrived on the same queue; one arrived for {quiet_id!r}"
    )

    # Second independent observable of the same absence: the drained queue reports nothing pending.
    pending = _retrying(
        lambda: sqs.get_queue_attributes(
            QueueUrl=queue_url,
            AttributeNames=["ApproximateNumberOfMessages", "ApproximateNumberOfMessagesNotVisible"],
        )
    )["Attributes"]
    assert pending["ApproximateNumberOfMessages"] == "0", (
        f"after draining, the queue must report no visible messages; "
        f"ApproximateNumberOfMessages={pending['ApproximateNumberOfMessages']!r}. An empty receive "
        f"alone would not distinguish 'nothing was sent' from 'nothing was received'"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
