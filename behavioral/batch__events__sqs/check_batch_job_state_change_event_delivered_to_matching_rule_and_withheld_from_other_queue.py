"""batch-job-state-change-event-delivered-to-matching-rule-and-withheld-from-other-queue."""

from __future__ import annotations

import json
import time
import uuid

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "batch-job-state-change-event-delivered-to-matching-rule-and-withheld-from-other-queue"
GROUP = "eventing"
SERVICES = ["batch", "events", "sqs"]


_MANAGED_TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"}
_UNMANAGED_ROLE_PREFIX = "sim2real-behav-batch-svc-"
_BATCH_SERVICE_POLICY = "arn:aws:iam::aws:policy/service-role/AWSBatchServiceRole"
_BATCH_TRUST_POLICY = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {"Service": "batch.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }
    ],
}
# Bounded deadlines, each with its reason. Never a bare sleep standing in for a wait.
_CE_VALID_S = 180       # an UNMANAGED CE has no capacity to provision, so it validates fast
_JQ_VALID_S = 180       # queue VALID follows CE association
_RUNNABLE_S = 180       # SUBMITTED -> RUNNABLE is a scheduler sweep, not a placement
_TERMINAL_S = 300       # a cancel of an unplaced job is bookkeeping, not a container stop
_TEARDOWN_S = 300       # DISABLED -> settle -> deleted -> gone, per resource


_NOT_FOUND = ("NoSuchEntity", "ResourceNotFoundException", "QueueDoesNotExist",
              "AWS.SimpleQueueService.NonExistentQueue")


def _swallow(fn):
    """Run a teardown step fn(); return when the resource is already gone, raise anything else."""
    try:
        fn()
    except ClientError as exc:
        err = exc.response["Error"]
        msg = err.get("Message", "")
        if err["Code"] not in _NOT_FOUND and not (
            err["Code"] == "ClientException" and ("does not exist" in msg or "not found" in msg)
        ):
            raise


def _delete_while_in_use(fn, timeout_s=60.0):
    """Run a Batch delete, retrying every 2 s while Batch refuses it for a dependency still
    draining (ClientException); not-found returns, anything else or the deadline raises."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            _swallow(fn)
            return
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ClientException" or time.monotonic() >= deadline:
                raise
        time.sleep(2)




def _teardown_left(teardown_deadline):
    """Seconds left of one deadline shared by every teardown wait, so all fit the cleanup budget."""
    deadline = teardown_deadline.setdefault("t", time.monotonic() + 570.0)
    return max(1.0, deadline - time.monotonic())


def _tags_kv():
    return [{"Key": k, "Value": v} for k, v in _MANAGED_TAGS.items()]


def _poll_until(probe, predicate, *, timeout_s=60, interval_s=1.0, description="condition"):
    """Poll probe() until predicate(result); RAISE on deadline miss, never return the last value."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _wait_role_assumable(ctx, role_name):
    """Bounded wait for a freshly-minted role to be readable by IAM's own read path.

    IAM create is eventually consistent and Batch rejects a role it cannot yet resolve. GetRole
    is the only condition observable from here, so the wait is bounded and raises.
    """
    iam = ctx.client("iam")
    _poll_until(
        lambda: iam.get_role(RoleName=role_name).get("Role"),
        lambda r: bool(r and r.get("Arn")),
        timeout_s=60,
        interval_s=3,
        description=f"IAM role {role_name} readable after create",
    )


def _delete_role(ctx, role_name, policy_arn):
    iam = ctx.client("iam")
    _swallow(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn))
    _swallow(lambda: iam.delete_role(RoleName=role_name))


def _batch_service_role_arn(ctx):
    """Create this run's own customer-managed Batch service role for an UNMANAGED CE.

    A fresh name per run, so no role the account already holds is adopted and no concurrent
    check's teardown can delete the role this check's compute environment runs under.
    """
    iam = ctx.client("iam")
    name = ctx.unique_name(_UNMANAGED_ROLE_PREFIX)
    arn = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=json.dumps(_BATCH_TRUST_POLICY),
        Description="SimParity behavioral suite: Batch service role for UNMANAGED CEs",
        Tags=_tags_kv(),
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: _delete_role(ctx, name, _BATCH_SERVICE_POLICY))
    iam.attach_role_policy(RoleName=name, PolicyArn=_BATCH_SERVICE_POLICY)
    _wait_role_assumable(ctx, name)
    return arn


def _describe_ce(bat, name):
    envs = bat.describe_compute_environments(computeEnvironments=[name]).get(
        "computeEnvironments", []
    )
    return envs[0] if envs else None


def _describe_jq(bat, name):
    qs = bat.describe_job_queues(jobQueues=[name]).get("jobQueues", [])
    return qs[0] if qs else None


def _describe_job(bat, job_id):
    js = bat.describe_jobs(jobs=[job_id]).get("jobs", [])
    return js[0] if js else None


def _wait_ce(bat, name, statuses, timeout_s=_CE_VALID_S, interval_s=3):
    return _poll_until(
        lambda: _describe_ce(bat, name),
        lambda ce: ce is not None and ce.get("status") in statuses,
        timeout_s=timeout_s,
        interval_s=interval_s,
        description=f"compute environment {name} status in {sorted(statuses)}",
    )


def _wait_jq(bat, name, statuses, timeout_s=_JQ_VALID_S, interval_s=3):
    return _poll_until(
        lambda: _describe_jq(bat, name),
        lambda jq: jq is not None and jq.get("status") in statuses,
        timeout_s=timeout_s,
        interval_s=interval_s,
        description=f"job queue {name} status in {sorted(statuses)}",
    )


def _teardown_jobs(bat, job_ids, teardown_deadline):
    """Terminate every non-terminal job, then wait for each to be terminal.

    A queue cannot be deleted while it holds non-terminal jobs and a CE cannot be deleted while
    a queue references it, so this MUST complete before the queue teardown. Registered before
    the queue so ctx's reverse order runs it first.
    """
    for jid in list(job_ids):
        _swallow(lambda jid=jid: bat.terminate_job(jobId=jid, reason="behavioral-test-cleanup"))
    for jid in list(job_ids):
        _poll_until(
            lambda jid=jid: _describe_job(bat, jid),
            lambda j: j is None or j.get("status") in ("SUCCEEDED", "FAILED"),
            timeout_s=min(_TEARDOWN_S, _teardown_left(teardown_deadline)),
            interval_s=2,
            description=f"job {jid} terminal before queue teardown",
        )


def _teardown_jq(bat, name, teardown_deadline):
    """DISABLE -> poll settled -> DeleteJobQueue -> poll gone."""
    _swallow(lambda: bat.update_job_queue(jobQueue=name, state="DISABLED"))
    _wait_jq(
        bat, name, {"VALID", "INVALID"}, timeout_s=min(_TEARDOWN_S, _teardown_left(teardown_deadline)), interval_s=2
    )
    _delete_while_in_use(
        lambda: bat.delete_job_queue(jobQueue=name), timeout_s=min(60.0, _teardown_left(teardown_deadline))
    )
    _poll_until(
        lambda: _describe_jq(bat, name),
        lambda jq: jq is None,
        timeout_s=min(_TEARDOWN_S, _teardown_left(teardown_deadline)),
        interval_s=2,
        description=f"job queue {name} gone",
    )


def _teardown_ce(bat, name, teardown_deadline):
    """DISABLE -> poll settled -> DeleteComputeEnvironment -> poll gone."""
    _swallow(lambda: bat.update_compute_environment(computeEnvironment=name, state="DISABLED"))
    _wait_ce(
        bat, name, {"VALID", "INVALID"}, timeout_s=min(_TEARDOWN_S, _teardown_left(teardown_deadline)), interval_s=2
    )
    _delete_while_in_use(
        lambda: bat.delete_compute_environment(computeEnvironment=name),
        timeout_s=min(60.0, _teardown_left(teardown_deadline)),
    )
    _poll_until(
        lambda: _describe_ce(bat, name),
        lambda ce: ce is None,
        timeout_s=min(_TEARDOWN_S, _teardown_left(teardown_deadline)),
        interval_s=2,
        description=f"compute environment {name} gone",
    )



def _register_jd(ctx, bat):
    """A trivial container job definition. It is never actually run on an UNMANAGED CE."""
    name = ctx.unique_name("sim2real-behav-jd-")
    resp = bat.register_job_definition(
        jobDefinitionName=name,
        type="container",
        containerProperties={
            "image": "public.ecr.aws/docker/library/busybox:1.36",
            "command": ["/bin/sh", "-c", "exit 0"],
            "resourceRequirements": [
                {"type": "VCPU", "value": "1"},
                {"type": "MEMORY", "value": "512"},
            ],
        },
        tags=dict(_MANAGED_TAGS),
    )
    rev = resp["revision"]
    ctx.on_cleanup(
        lambda: _swallow(lambda: bat.deregister_job_definition(jobDefinition=f"{name}:{rev}"))
    )
    return f"{name}:{rev}"




_BATCH_SOURCE = "aws.batch"
_BATCH_DETAIL_TYPE = "Batch Job State Change"
_WARMUP_SOURCE = "sim2real.batch.warmup"
_MIN_HOLD_S = 180   # absence-window floor, so a fast latency cannot undercut one delivery
_MAX_HOLD_S = 420   # ceiling, so a pathologically slow control cannot blow the whole budget
_EVENT_S = 300      # a service-emitted event through EventBridge to SQS


def _sqs_queue(ctx, region, account):
    """An SQS queue whose policy lets EventBridge rules in this account deliver. (url, arn)."""
    sqs = ctx.client("sqs")
    url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-behav-batchev-"),
        tags=dict(_MANAGED_TAGS),
    )["QueueUrl"]
    ctx.on_cleanup(lambda: _swallow(lambda: sqs.delete_queue(QueueUrl=url)))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"][
        "QueueArn"
    ]
    sqs.set_queue_attributes(
        QueueUrl=url,
        Attributes={
            "Policy": json.dumps(
                {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Sid": "AllowEventBridge",
                            "Effect": "Allow",
                            "Principal": {"Service": "events.amazonaws.com"},
                            "Action": "sqs:SendMessage",
                            "Resource": arn,
                            "Condition": {
                                "ArnLike": {
                                    "aws:SourceArn": f"arn:aws:events:{region}:{account}:rule/*"
                                }
                            },
                        }
                    ],
                }
            )
        },
    )
    return url, arn


def _rule(ctx, pattern, queue_arn, *, label):
    """Create an ENABLED default-bus rule targeting an SQS queue. Returns the rule name.

    Cleanup removes the TARGET first: EventBridge refuses DeleteRule while a target remains, so
    the reverse order ctx uses would otherwise leak the rule.
    """
    ev = ctx.client("events")
    name = ctx.unique_name(f"sim2real-behav-{label}-")
    ev.put_rule(
        Name=name,
        EventPattern=json.dumps(pattern),
        State="ENABLED",
        Tags=_tags_kv(),
    )
    ctx.on_cleanup(lambda: _swallow(lambda: ev.delete_rule(Name=name, Force=True)))
    resp = ev.put_targets(Rule=name, Targets=[{"Id": "q", "Arn": queue_arn}])
    ctx.on_cleanup(lambda: _swallow(lambda: ev.remove_targets(Rule=name, Ids=["q"], Force=True)))
    assert resp["FailedEntryCount"] == 0, (
        f"put_targets for rule {name!r} reported {resp['FailedEntryCount']} failures: "
        f"{resp.get('FailedEntries')!r}"
    )
    return name


def _drain(ctx, url):
    """Receive and delete everything currently visible. Returns the parsed event envelopes."""
    sqs = ctx.client("sqs")
    resp = sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=10, WaitTimeSeconds=5)
    msgs = resp.get("Messages", [])
    if msgs:
        sqs.delete_message_batch(
            QueueUrl=url,
            Entries=[{"Id": f"d{i}", "ReceiptHandle": m["ReceiptHandle"]} for i, m in enumerate(msgs)],
        )
    return [json.loads(m["Body"]) for m in msgs]


def _drain_to_empty(ctx, url):
    """Drain to two consecutive empty receives, so a later arrival is a REAL arrival."""
    empties = 0
    deadline = time.monotonic() + 120
    while time.monotonic() < deadline and empties < 2:
        empties = empties + 1 if not _drain(ctx, url) else 0
    assert empties >= 2, f"queue {url!r} would not drain to empty within 120s"


def _warm_up(ctx, url, queue_arn, label):
    """Prove this exact wiring can deliver, using a throwaway rule on a source we control.

    An SQS resource policy becomes effective asynchronously and exposes no condition to poll, and
    EventBridge drops undeliverable events silently with FailedEntryCount 0. So the warm-up is a
    bounded retry against an OBSERVABLE condition (a message actually arriving), never a sleep.
    Returns the measured warm-up delivery latency in seconds.
    """
    ev = ctx.client("events")
    token = uuid.uuid4().hex
    rule_name = _rule(
        ctx,
        {"source": [_WARMUP_SOURCE], "detail": {"token": [token]}},
        queue_arn,
        label=f"warm-{label}",
    )
    started = time.monotonic()
    deadline = started + 240
    while time.monotonic() < deadline:
        resp = ev.put_events(
            Entries=[
                {
                    "Source": _WARMUP_SOURCE,
                    "DetailType": "sim2real warm-up",
                    "Detail": json.dumps({"token": token}),
                }
            ]
        )
        assert resp["FailedEntryCount"] == 0, (
            f"warm-up put_events for {label} was rejected: {resp!r}"
        )
        for envelope in _drain(ctx, url):
            if envelope.get("detail", {}).get("token") == token:
                latency = time.monotonic() - started
                _swallow(lambda: ev.remove_targets(Rule=rule_name, Ids=["q"], Force=True))
                _swallow(lambda: ev.delete_rule(Name=rule_name, Force=True))
                _drain_to_empty(ctx, url)
                return latency
        time.sleep(5)
    raise AssertionError(
        f"the {label} wiring never delivered a warm-up event within 240s, so nothing this check "
        f"observes on it would be evidence; queue={url!r} rule={rule_name!r}"
    )


def _batch_events(ctx, url, sink):
    """Drain `url`, keep every Batch job state change envelope in `sink`, return `sink`."""
    for envelope in _drain(ctx, url):
        if (
            envelope.get("source") == _BATCH_SOURCE
            and envelope.get("detail-type") == _BATCH_DETAIL_TYPE
        ):
            sink.append(envelope)
    return sink


def _await_event(ctx, url, sink, *, job_id, status, timeout_s, description):
    """Poll until an event for (job_id, status) has been collected. RAISES on the deadline."""

    def _found():
        _batch_events(ctx, url, sink)
        return [
            e
            for e in sink
            if e["detail"].get("jobId") == job_id and e["detail"].get("status") == status
        ]

    return _poll_until(
        _found,
        lambda matches: bool(matches),
        timeout_s=timeout_s,
        interval_s=5,
        description=description,
    )


def _queue_depth(ctx, url):
    """(visible, in-flight) message counts — the second observable for an absence claim."""
    attrs = ctx.client("sqs").get_queue_attributes(
        QueueUrl=url,
        AttributeNames=["ApproximateNumberOfMessages", "ApproximateNumberOfMessagesNotVisible"],
    )["Attributes"]
    return (
        int(attrs["ApproximateNumberOfMessages"]),
        int(attrs["ApproximateNumberOfMessagesNotVisible"]),
    )


def _job_queue_on(ctx, bat, ce_arn, teardown_deadline):
    """An ENABLED job queue on an existing CE, polled to VALID. Returns (name, arn)."""
    jq_name = ctx.unique_name("sim2real-behav-jq-")
    arn = bat.create_job_queue(
        jobQueueName=jq_name,
        state="ENABLED",
        priority=10,
        computeEnvironmentOrder=[{"order": 1, "computeEnvironment": ce_arn}],
        tags=dict(_MANAGED_TAGS),
    )["jobQueueArn"]
    ctx.on_cleanup(lambda: _teardown_jq(bat, jq_name, teardown_deadline))
    jq = _wait_jq(bat, jq_name, {"VALID", "INVALID"})
    assert jq["status"] == "VALID", (
        f"job queue {jq_name} must reach VALID, got {jq['status']!r}: {jq.get('statusReason')!r}"
    )
    return jq_name, arn


def _unmanaged_ce(ctx, bat, teardown_deadline):
    """UNMANAGED CE only (no queue). Jobs on queues attached to it park in RUNNABLE forever."""
    ce_name = ctx.unique_name("sim2real-behav-ce-unmgd-")
    role = _batch_service_role_arn(ctx)
    ce_arn = None
    for attempt in range(8):
        try:
            ce_arn = bat.create_compute_environment(
                computeEnvironmentName=ce_name,
                type="UNMANAGED",
                state="ENABLED",
                serviceRole=role,
                tags=dict(_MANAGED_TAGS),
            )["computeEnvironmentArn"]
            break
        except Exception as exc:  # noqa: BLE001 - only an IAM-propagation 400 is retryable
            msg = str(exc).lower()
            if not ("cannot be assumed" in msg or "sts:assumerole" in msg) or attempt == 7:
                raise
            time.sleep(5)
    assert ce_arn, f"create_compute_environment never returned an ARN for {ce_name}"
    ctx.on_cleanup(lambda: _teardown_ce(bat, ce_name, teardown_deadline))
    ce = _wait_ce(bat, ce_name, {"VALID", "INVALID"})
    assert ce["status"] == "VALID", (
        f"UNMANAGED compute environment {ce_name} must reach VALID, got {ce['status']!r}: "
        f"{ce.get('statusReason')!r}"
    )
    return ce_arn


@tags(
    "axis:negative-delivery",
    "cap:c3",
    "cap:c4",
    "concern:eventing",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """A Batch job state change reaches SQS through a rule on its job queue ARN, is withheld from a
    rule pinned to a sibling queue over a latency-calibrated window, and arrives there once a job is
    submitted to that sibling queue."""
    # One teardown deadline per run, started by the first teardown that runs.
    teardown_deadline: dict = {}
    bat = ctx.client("batch")
    account = ctx.client("sts").get_caller_identity()["Account"]
    assert account, "STS returned no account id; refusing to run against an unidentified target"
    region = ctx.region

    ce_arn = _unmanaged_ce(ctx, bat, teardown_deadline)
    watched_jq, watched_jq_arn = _job_queue_on(ctx, bat, ce_arn, teardown_deadline)
    sibling_jq, sibling_jq_arn = _job_queue_on(ctx, bat, ce_arn, teardown_deadline)
    assert watched_jq_arn != sibling_jq_arn, (
        f"the two job queues must have distinct ARNs for the pattern to discriminate; both are "
        f"{watched_jq_arn!r}"
    )

    watched_url, watched_arn = _sqs_queue(ctx, region, account)
    sibling_url, sibling_arn = _sqs_queue(ctx, region, account)

    # --- layer 1: prove BOTH wirings can deliver, before either is used as evidence ------------
    # An UNMANAGED CE means no container runs; SUBMITTED itself emits no event, RUNNABLE is first.
    watched_warm_s = _warm_up(ctx, watched_url, watched_arn, "watched")
    sibling_warm_s = _warm_up(ctx, sibling_url, sibling_arn, "sibling")
    assert watched_warm_s > 0 and sibling_warm_s > 0, (
        f"both warm-ups must have measured a real latency; got watched={watched_warm_s!r} "
        f"sibling={sibling_warm_s!r}"
    )

    _rule(
        ctx,
        {
            "source": [_BATCH_SOURCE],
            "detail-type": [_BATCH_DETAIL_TYPE],
            "detail": {"jobQueue": [watched_jq_arn]},
        },
        watched_arn,
        label="watch",
    )
    _rule(
        ctx,
        {
            "source": [_BATCH_SOURCE],
            "detail-type": [_BATCH_DETAIL_TYPE],
            "detail": {"jobQueue": [sibling_jq_arn]},
        },
        sibling_arn,
        label="sibling",
    )
    _drain_to_empty(ctx, watched_url)
    _drain_to_empty(ctx, sibling_url)

    job_def = _register_jd(ctx, bat)
    watched_sink: list = []
    sibling_sink: list = []

    # --- the delivered event, observed at the CONSUMER (SQS), not at Batch --------------------
    t0 = time.monotonic()
    job_id = bat.submit_job(
        jobName=ctx.unique_name("sim2real-behav-job-"),
        jobQueue=watched_jq,
        jobDefinition=job_def,
    )["jobId"]
    ctx.on_cleanup(lambda: _teardown_jobs(bat, [job_id], teardown_deadline))
    job_arn = _poll_until(
        lambda: _describe_job(bat, job_id),
        lambda j: j is not None and j.get("jobArn"),
        timeout_s=_RUNNABLE_S,
        interval_s=3,
        description=f"DescribeJobs reports an ARN for job {job_id}",
    )["jobArn"]

    matches = _await_event(
        ctx,
        watched_url,
        watched_sink,
        job_id=job_id,
        status="RUNNABLE",
        timeout_s=_EVENT_S,
        description=(
            f"a RUNNABLE Batch Job State Change event for job {job_id} arrives on the watched "
            f"SQS queue"
        ),
    )
    latency_s = time.monotonic() - t0
    event = matches[0]

    assert event["source"] == _BATCH_SOURCE, (
        f"the envelope's source must be {_BATCH_SOURCE!r}, got {event.get('source')!r}"
    )
    assert event["detail-type"] == _BATCH_DETAIL_TYPE, (
        f"the envelope's detail-type must be {_BATCH_DETAIL_TYPE!r}, got "
        f"{event.get('detail-type')!r}"
    )
    assert event["account"] == account, (
        f"the envelope's account must be the caller's ({account}), got {event.get('account')!r}"
    )
    assert event["region"] == region, (
        f"the envelope's region must be {region!r}, got {event.get('region')!r}"
    )
    assert event["resources"] == [job_arn], (
        f"the envelope's resources must be exactly the job ARN [{job_arn!r}], got "
        f"{event.get('resources')!r}"
    )
    detail = event["detail"]
    assert detail["jobId"] == job_id, (
        f"detail.jobId must be the submitted job {job_id!r}, got {detail.get('jobId')!r}"
    )
    assert detail["jobArn"] == job_arn, (
        f"detail.jobArn must match the ARN DescribeJobs reports ({job_arn!r}), got "
        f"{detail.get('jobArn')!r}"
    )
    assert detail["jobQueue"] == watched_jq_arn, (
        f"detail.jobQueue must be the watched queue's ARN ({watched_jq_arn!r}), got "
        f"{detail.get('jobQueue')!r} — a wrong value here would also mean the rule pattern matched "
        f"for the wrong reason"
    )
    assert detail["status"] == "RUNNABLE", (
        f"detail.status must be the state the job transitioned INTO, got {detail.get('status')!r}"
    )
    assert detail["jobDefinition"].startswith("arn:"), (
        f"detail.jobDefinition must be the job definition ARN, got "
        f"{detail.get('jobDefinition')!r}"
    )
    assert isinstance(detail["createdAt"], int), (
        f"detail.createdAt must be an epoch-millis integer as DescribeJobs reports it, got "
        f"{detail.get('createdAt')!r}"
    )
    # The detail must agree with the API's own view of the same job, so an invented event body
    # rather than a projection of the job record fails here.
    api_job = _describe_job(bat, job_id)
    assert detail["jobName"] == api_job["jobName"], (
        f"detail.jobName must equal what DescribeJobs reports for the same job; event says "
        f"{detail.get('jobName')!r}, API says {api_job.get('jobName')!r}"
    )
    assert detail["createdAt"] == api_job["createdAt"], (
        f"detail.createdAt must equal what DescribeJobs reports; event says "
        f"{detail['createdAt']!r}, API says {api_job.get('createdAt')!r}"
    )

    # --- layer 2: the sibling wiring must be EMPTY over a window calibrated on that latency ----
    hold_s = min(max(3 * latency_s, _MIN_HOLD_S), _MAX_HOLD_S)
    deadline = time.monotonic() + hold_s
    samples = 0
    while time.monotonic() < deadline:
        stray = _batch_events(ctx, sibling_url, sibling_sink)
        assert not stray, (
            f"the sibling rule pins jobQueue={sibling_jq_arn!r} and no job has been submitted "
            f"there, so it must receive NOTHING during the {hold_s:.0f}s window (3x the measured "
            f"{latency_s:.0f}s delivery latency); it received "
            f"{[(e['detail'].get('jobId'), e['detail'].get('status')) for e in stray]}"
        )
        samples += 1
        time.sleep(2)
    assert samples >= 3, (
        f"the absence window must be sampled at least 3 times to be evidence, sampled {samples} "
        f"times over {hold_s:.0f}s"
    )
    visible, in_flight = _queue_depth(ctx, sibling_url)
    assert (visible, in_flight) == (0, 0), (
        f"SQS's own counters are the second observable for the absence: the sibling queue must "
        f"report 0 visible and 0 in-flight messages, got {visible} visible and {in_flight} "
        f"in-flight"
    )

    # --- a SECOND transition on the watched job: the stream tracks transitions, plural ---------
    terminate_reason = f"sim2real-terminate-{uuid.uuid4().hex[:12]}"
    bat.terminate_job(jobId=job_id, reason=terminate_reason)
    failed_events = _await_event(
        ctx,
        watched_url,
        watched_sink,
        job_id=job_id,
        status="FAILED",
        timeout_s=_EVENT_S,
        description=(
            f"a FAILED Batch Job State Change event for job {job_id} arrives after TerminateJob"
        ),
    )
    failed_detail = failed_events[0]["detail"]
    assert failed_detail["jobId"] == job_id, (
        f"the FAILED event must be for the same job; got {failed_detail.get('jobId')!r}"
    )
    assert terminate_reason in (failed_detail.get("statusReason") or ""), (
        f"the FAILED event's detail.statusReason must carry the reason passed to TerminateJob; "
        f"expected {terminate_reason!r} inside {failed_detail.get('statusReason')!r}"
    )
    observed_statuses = {
        e["detail"].get("status") for e in watched_sink if e["detail"].get("jobId") == job_id
    }
    assert {"RUNNABLE", "FAILED"} <= observed_statuses, (
        f"the event stream must report BOTH transitions for job {job_id}; observed statuses were "
        f"{sorted(observed_statuses)}"
    )
    assert "SUBMITTED" not in observed_statuses, (
        f"the User Guide is explicit that no event is created for the initial job submission, so "
        f"no SUBMITTED event may appear; observed {sorted(observed_statuses)}"
    )

    # --- layer 3: repair exactly the withheld thing and DEMAND delivery ------------------------
    sibling_job = bat.submit_job(
        jobName=ctx.unique_name("sim2real-behav-job-"),
        jobQueue=sibling_jq,
        jobDefinition=job_def,
    )["jobId"]
    ctx.on_cleanup(lambda: _teardown_jobs(bat, [sibling_job], teardown_deadline))
    sibling_matches = _await_event(
        ctx,
        sibling_url,
        sibling_sink,
        job_id=sibling_job,
        status="RUNNABLE",
        timeout_s=_EVENT_S,
        description=(
            f"once a job IS submitted to the sibling queue, its RUNNABLE event arrives there "
            f"(job {sibling_job})"
        ),
    )
    assert sibling_matches[0]["detail"]["jobQueue"] == sibling_jq_arn, (
        f"the sibling queue's event must name the sibling queue's ARN ({sibling_jq_arn!r}), got "
        f"{sibling_matches[0]['detail'].get('jobQueue')!r}"
    )
    delivered_to_sibling = {
        e["detail"].get("jobId") for e in sibling_sink
    }
    assert job_id not in delivered_to_sibling, (
        f"the first job's events must NEVER have reached the sibling queue, not even late; the "
        f"sibling queue has now seen job ids {sorted(delivered_to_sibling)}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
