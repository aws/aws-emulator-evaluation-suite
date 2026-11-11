"""eventbridge-project-name-filter-delivers-only-the-named-projects-build-events."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

# Three builds in two rounds plus a latency-calibrated absence window: expect ~15 minutes.

_SCENARIO = "codebuild-event-filter"
_IMAGE = "aws/codebuild/standard:7.0"

_BUILDSPEC = (
    "version: 0.2\n"
    "phases:\n"
    "  build:\n"
    "    commands:\n"
    "      - echo sim2real-event-probe\n"
)


def _delete_role(iam, role_name):
    """Delete an IAM role after its inline policies, tolerating NoSuchEntity."""
    try:
        for pname in iam.list_role_policies(RoleName=role_name).get("PolicyNames", []):
            try:
                iam.delete_role_policy(RoleName=role_name, PolicyName=pname)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "NoSuchEntity":
                    raise
        iam.delete_role(RoleName=role_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _create_service_role(ctx, statements):
    """Mint a real CodeBuild-assumable service role carrying exactly `statements`."""
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-role-codebuild-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "codebuild.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }],
    }
    resp = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Path="/sim2real/",
        Tags=[{"Key": "sim2real", "Value": _SCENARIO}],
    )
    ctx.on_cleanup(lambda: _delete_role(iam, role_name))
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName="codebuild-inline",
        PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": statements}),
    )
    return resp["Role"]["Arn"]


def _create_project(cb, ctx, name, role_arn, **over):
    """CreateProject on NO_SOURCE + an inline buildspec, retrying through IAM trust-policy
    propagation; registers teardown immediately on success. Returns the project dict."""
    args = {
        "name": name,
        "source": {"type": "NO_SOURCE", "buildspec": _BUILDSPEC},
        "artifacts": {"type": "NO_ARTIFACTS"},
        "cache": {"type": "NO_CACHE"},
        "environment": {"type": "LINUX_CONTAINER", "image": _IMAGE,
                        "computeType": "BUILD_GENERAL1_SMALL"},
        "serviceRole": role_arn,
        "logsConfig": {"cloudWatchLogs": {"status": "DISABLED"},
                       "s3Logs": {"status": "DISABLED"}},
        "timeoutInMinutes": 5,
        "tags": [{"key": "sim2real", "value": _SCENARIO}],
    }
    args.update(over)
    # Trust propagation exposes no condition to poll, so this bounded retry IS the wait.
    deadline = time.monotonic() + 180
    while True:
        try:
            proj = cb.create_project(**args)["project"]
            break
        except ClientError as exc:
            err = exc.response.get("Error", {})
            msg = (err.get("Message") or "").lower()
            transient_role = err.get("Code") == "InvalidInputException" and (
                "assume" in msg or "not authorized" in msg)
            if transient_role and time.monotonic() < deadline:
                time.sleep(3)
                continue
            raise
    ctx.on_cleanup(lambda: cb.delete_project(name=proj["name"]))
    return proj


def _stop(cb, build_id):
    try:
        cb.stop_build(id=build_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _register_stop(cb, ctx):
    """Register the StopBuild cleanup BEFORE any build id exists, so a build that starts and then
    trips an assertion still gets stopped instead of billing out its timeout."""
    holder = {"id": None}
    ctx.on_cleanup(lambda: holder["id"] and _stop(cb, holder["id"]))
    return holder


def _get_builds(cb, ids):
    got = cb.batch_get_builds(ids=list(ids))
    by_id = {b["id"]: b for b in got.get("builds", [])}
    missing = [i for i in ids if i not in by_id]
    assert not missing, (
        f"BatchGetBuilds lost {missing!r}; asked for {list(ids)!r}, got {sorted(by_id)!r} "
        f"and buildsNotFound={got.get('buildsNotFound')!r}"
    )
    return by_id


def _poll_builds_terminal(cb, ids, *, timeout_s, interval_s=5.0):
    """Poll one BatchGetBuilds over every id until all report buildComplete, bounded by a
    deadline. Raises on timeout rather than returning incomplete builds."""
    deadline = time.monotonic() + timeout_s
    while True:
        by_id = _get_builds(cb, ids)
        pending = [i for i, b in by_id.items() if b.get("buildComplete") is not True]
        if not pending:
            return by_id
        assert time.monotonic() < deadline, (
            f"after {timeout_s}s these builds never reported buildComplete: "
            f"{[(i, by_id[i].get('buildStatus'), by_id[i].get('currentPhase')) for i in pending]!r}"
        )
        time.sleep(interval_s)


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _wait_counters_zero(ctx, sqs, queue_url, names, *, cap_s=90.0, interval_s=3.0):
    """Read the queue's *names* counters until each is "0" or cap_s ends; return the last read.

    SQS documents these counters as eventually consistent: they "may not achieve consistency until
    at least 1 minute after the producers stop sending messages" (GetQueueAttributes). A stop forced
    by the runner's budget, short of cap_s, is no verdict.
    """
    start = time.monotonic()
    budget_s = _budget_s(ctx, cap_s)
    deadline = start + budget_s
    while True:
        attrs = sqs.get_queue_attributes(
            QueueUrl=queue_url, AttributeNames=list(names))["Attributes"]
        if all(attrs.get(n) == "0" for n in names):
            return attrs
        if time.monotonic() >= deadline:
            if budget_s < cap_s:
                raise TimeoutError(
                    f"the check's time budget ran out after {time.monotonic() - start:.1f}s, before "
                    f"the {cap_s}s wait ended (last={attrs!r}); not graded"
                )
            return attrs
        time.sleep(interval_s)


def _phases(build):
    return [(p.get("phaseType"), p.get("phaseStatus")) for p in build.get("phases", [])]


def _make_queue(ctx):
    """Create an SQS queue and return (url, arn)."""
    sqs = ctx.client("sqs")
    qname = ctx.unique_name("sim2real-behav-cb-events-")
    url = sqs.create_queue(QueueName=qname,
                           tags={"sim2real": _SCENARIO})["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    arn = sqs.get_queue_attributes(
        QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    return url, arn


def _pattern(project_names):
    return {
        "source": ["aws.codebuild"],
        "detail-type": ["CodeBuild Build State Change"],
        "detail": {"project-name": list(project_names)},
    }


def _put_rule(ctx, rule_name, project_names):
    """PutRule with the given project-name filter; on an existing name it replaces the pattern."""
    events = ctx.client("events")
    return events.put_rule(
        Name=rule_name,
        EventPattern=json.dumps(_pattern(project_names)),
        State="ENABLED",
        Description="sim2real behavioral: codebuild build state change filter",
        Tags=[{"Key": "sim2real", "Value": _SCENARIO}],
    )["RuleArn"]


def _drain(ctx, queue_url):
    """Receive everything currently visible on the queue, deleting as it goes, and return the
    raw bodies. Long-polls once per pass so a message in flight is not missed."""
    sqs = ctx.client("sqs")
    bodies = []
    while True:
        resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=10,
                                  WaitTimeSeconds=5, VisibilityTimeout=60)
        msgs = resp.get("Messages", [])
        if not msgs:
            return bodies
        for m in msgs:
            bodies.append(m["Body"])
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=m["ReceiptHandle"])


def _collect_until(ctx, queue_url, predicate, *, timeout_s):
    """Drain repeatedly, accumulating bodies, until `predicate(bodies)` holds or the deadline
    passes. Returns (bodies, elapsed_seconds, satisfied)."""
    started = time.monotonic()
    deadline = started + timeout_s
    bodies = []
    while True:
        bodies.extend(_drain(ctx, queue_url))
        if predicate(bodies):
            return bodies, time.monotonic() - started, True
        if time.monotonic() >= deadline:
            return bodies, time.monotonic() - started, False


def _events(bodies):
    """Parse the EventBridge envelopes, keeping the raw body alongside each."""
    out = []
    for body in bodies:
        try:
            out.append((json.loads(body), body))
        except json.JSONDecodeError:
            out.append(({}, body))
    return out


def _for_project(bodies, project):
    return [(env, raw) for env, raw in _events(bodies)
            if (env.get("detail") or {}).get("project-name") == project]


# ===== check =====

CHECK = "eventbridge-project-name-filter-delivers-only-the-named-projects-build-events"
GROUP = 'event-propagation'
SERVICES = ['codebuild', 'events']


@tags("axis:negative-delivery", "cap:c3", "cap:c4", "concern:data-plane", "concern:e2e",
      "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """A rule filtering detail.project-name delivers the named project's build events to SQS and
    none for a second project built alongside; widening the pattern makes its next build deliver.

    Reference: https://docs.aws.amazon.com/codebuild/latest/userguide/sample-build-notifications.html
    """
    cb = ctx.client("codebuild")
    sqs = ctx.client("sqs")
    events = ctx.client("events")
    account = ctx.client("sts").get_caller_identity()["Account"]

    queue_url, queue_arn = _make_queue(ctx)

    named = ctx.unique_name("sim2real-behav-proj-evnamed-")
    unnamed = ctx.unique_name("sim2real-behav-proj-evother-")
    rule_name = ctx.unique_name("sim2real-behav-cb-rule-")

    rule_arn = _put_rule(ctx, rule_name, [named])
    ctx.on_cleanup(lambda: events.delete_rule(Name=rule_name, Force=True))
    sqs.set_queue_attributes(QueueUrl=queue_url, Attributes={"Policy": json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "events.amazonaws.com"},
            "Action": "sqs:SendMessage",
            "Resource": queue_arn,
            "Condition": {"ArnEquals": {"aws:SourceArn": rule_arn}},
        }],
    })})
    events.put_targets(Rule=rule_name, Targets=[{"Id": "sim2real-sqs", "Arn": queue_arn}])
    ctx.on_cleanup(lambda: events.remove_targets(Rule=rule_name, Ids=["sim2real-sqs"],
                                                 Force=True))

    role = _create_service_role(ctx, [
        {"Effect": "Allow",
         "Action": ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"],
         "Resource": "*"},
    ])
    # Both projects exist, and the rule exists, BEFORE either build runs: no propagation delta
    # can explain the difference between them. The only difference is the event pattern.
    _create_project(cb, ctx, named, role)
    _create_project(cb, ctx, unnamed, role)

    holder_a = _register_stop(cb, ctx)
    build_named = cb.start_build(projectName=named)["build"]
    holder_a["id"] = build_named["id"]
    holder_b = _register_stop(cb, ctx)
    build_unnamed = cb.start_build(projectName=unnamed)["build"]
    holder_b["id"] = build_unnamed["id"]

    finals = _poll_builds_terminal(
        cb, [build_named["id"], build_unnamed["id"]], timeout_s=300)
    final_named = finals[build_named["id"]]
    final_unnamed = finals[build_unnamed["id"]]
    for label, build in (("named", final_named), ("unnamed", final_unnamed)):
        assert build["buildStatus"] == "SUCCEEDED", (
            f"the {label} project's build must SUCCEED so that it definitely had a terminal "
            f"state change to publish; got {build['buildStatus']!r}; "
            f"phases={_phases(build)!r}; "
            f"contexts={[p.get('contexts') for p in build.get('phases', [])]!r}"
        )

    # The named project's terminal event is the barrier; its latency calibrates the absence window.
    def _has_terminal(bodies):
        return any((env.get("detail") or {}).get("build-status") == "SUCCEEDED"
                   for env, _raw in _for_project(bodies, named))

    bodies, latency, satisfied = _collect_until(
        ctx, queue_url, _has_terminal, timeout_s=180)
    assert satisfied, (
        f"the barrier itself did not hold: no SUCCEEDED CodeBuild Build State Change event for "
        f"the NAMED project {named!r} reached {queue_url!r} within 180s. Without this event the "
        f"absence proved below would be meaningless. {len(bodies)} bodies arrived: "
        f"{[b[:200] for b in bodies[-4:]]!r}"
    )

    named_events = _for_project(bodies, named)
    terminal = [(env, raw) for env, raw in named_events
                if (env.get("detail") or {}).get("build-status") == "SUCCEEDED"]
    assert len(terminal) == 1, (
        f"a single SUCCEEDED build must publish exactly one SUCCEEDED state change; "
        f"{len(terminal)} arrived for {named!r}: "
        f"{[r[:200] for _e, r in terminal]!r}"
    )
    env, raw = terminal[0]
    assert env.get("source") == "aws.codebuild", (
        f"the event's source must be 'aws.codebuild', it is {env.get('source')!r}; "
        f"envelope {raw[:300]!r}"
    )
    assert env.get("detail-type") == "CodeBuild Build State Change", (
        f"the event's detail-type must be 'CodeBuild Build State Change', it is "
        f"{env.get('detail-type')!r}; envelope {raw[:300]!r}"
    )
    assert env.get("account") == account, (
        f"the event must be attributed to this account ({account!r}), it reports "
        f"{env.get('account')!r}"
    )
    assert env.get("region") == ctx.region, (
        f"the event must be attributed to {ctx.region!r}, it reports {env.get('region')!r}"
    )
    build_arn = final_named.get("arn")
    assert build_arn, f"the named build must report an arn, got {final_named.get('arn')!r}"
    reported_id = (env.get("detail") or {}).get("build-id")
    assert reported_id == build_arn, (
        f"detail.build-id must identify the build that finished: expected the build ARN "
        f"{build_arn!r}, the event carries {reported_id!r} (short id is "
        f"{final_named['id']!r})"
    )

    # An earlier IN_PROGRESS event, and the terminal one is not before it (envelope clock, not
    # SQS order - a standard queue does not preserve order).
    in_progress = [(e, r) for e, r in named_events
                   if (e.get("detail") or {}).get("build-status") == "IN_PROGRESS"]
    assert in_progress, (
        f"the build's start must also publish a state change; only "
        f"{[(e.get('detail') or {}).get('build-status') for e, _r in named_events]!r} arrived"
    )
    stamps = [e.get("time") for e, _r in in_progress] + [env.get("time")]
    assert all(isinstance(s, str) and s for s in stamps), (
        f"every EventBridge envelope must carry a non-empty `time`; got {stamps!r}"
    )
    assert env["time"] >= max(e["time"] for e, _r in in_progress), (
        f"the SUCCEEDED event's envelope time {env['time']!r} must not precede the "
        f"IN_PROGRESS events' {[e['time'] for e, _r in in_progress]!r}"
    )

    # Hold for max(3L, 15s), L being the named project's measured latency, then confirm with the
    # queue's depth attributes.
    window = max(3.0 * latency, 15.0)
    absence_deadline = time.monotonic() + window
    seen_after = []
    while time.monotonic() < absence_deadline:
        seen_after.extend(_drain(ctx, queue_url))
    all_bodies = bodies + seen_after
    leaked = [b for b in all_bodies if unnamed in b]
    assert leaked == [], (
        f"the rule's event pattern names only {named!r}, so NOTHING mentioning {unnamed!r} may "
        f"reach the queue - yet {len(leaked)} did, over a window of {window:.1f}s calibrated "
        f"from the named project's own {latency:.1f}s delivery latency: "
        f"{[b[:200] for b in leaked[:3]]!r}"
    )
    depth = _wait_counters_zero(
        ctx, sqs, queue_url,
        ["ApproximateNumberOfMessages", "ApproximateNumberOfMessagesNotVisible"])
    assert (int(depth["ApproximateNumberOfMessages"]) == 0
            and int(depth["ApproximateNumberOfMessagesNotVisible"]) == 0), (
        f"the second independent observable must agree that nothing is pending after the "
        f"{window:.1f}s absence window; the queue reports {depth!r}"
    )

    # Widening the pattern must restore delivery, proving the absence came from the filter.
    _put_rule(ctx, rule_name, [named, unnamed])
    described = json.loads(events.describe_rule(Name=rule_name)["EventPattern"])
    assert sorted(described["detail"]["project-name"]) == sorted([named, unnamed]), (
        f"the widened pattern must name both projects, DescribeRule reports "
        f"{described!r}"
    )
    holder_c = _register_stop(cb, ctx)
    repaired = cb.start_build(projectName=unnamed)["build"]
    holder_c["id"] = repaired["id"]
    final_repaired = _poll_builds_terminal(
        cb, [repaired["id"]], timeout_s=300)[repaired["id"]]
    assert final_repaired["buildStatus"] == "SUCCEEDED", (
        f"the repair build must SUCCEED; got {final_repaired['buildStatus']!r}; "
        f"phases={_phases(final_repaired)!r}"
    )

    def _has_repaired(bs):
        return any((e.get("detail") or {}).get("build-id") == final_repaired.get("arn")
                   for e, _r in _events(bs))

    repaired_bodies, _elapsed, ok = _collect_until(
        ctx, queue_url, _has_repaired, timeout_s=180)
    assert ok, (
        f"after widening the pattern to name {unnamed!r}, its next build "
        f"({final_repaired.get('arn')!r}) must deliver - proving the earlier absence was the "
        f"FILTER and not a missing delivery path. {len(repaired_bodies)} bodies arrived: "
        f"{[b[:200] for b in repaired_bodies[-4:]]!r}"
    )
    repaired_named = _for_project(repaired_bodies, unnamed)
    assert repaired_named, (
        f"the delivered events must be attributed to {unnamed!r} in "
        f"detail.project-name; the bodies carry "
        f"{[(e.get('detail') or {}).get('project-name') for e, _r in _events(repaired_bodies)]!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
