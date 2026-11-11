"""ecs-container-oom-kill-reason-matches-eventbridge-task-state-change-detail."""

from __future__ import annotations

import json
import sys
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "ecs-container-oom-kill-reason-matches-eventbridge-task-state-change-detail"

GROUP = "task-lifecycle"

SERVICES = ["ecs", "events", "logs", "sqs"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:e2e", "dp:api",
      "plane:data")
def run(ctx) -> None:
    """A container exceeding its container-level memory limit is OOM-killed with the same exact reason
    on DescribeTasks and in every STOPPED Task State Change event; an under-limit control exits 0.

    Reference: https://docs.aws.amazon.com/AmazonECS/latest/developerguide/ecs_task_events.html
    """
    ecs = ctx.client("ecs")
    ev = ctx.client("events")
    td = _Teardown(ctx)
    ok = False
    try:
        account = ctx.client("sts").get_caller_identity()["Account"]
        subnets, sg = _fargate_network(ctx)
        subject = _create_cluster(ctx, ecs, td, "subject")
        # An empty second cluster, so the non-matching rule below differs from the matching one in
        # exactly ONE field of its event pattern.
        other = _create_cluster(ctx, ecs, td, "other")
        _ensure_ecs_slr(ctx)
        log_group = _create_log_group(ctx, td)
        _e, exec_role = _iam_role(ctx, td, "exec", _EXEC_STATEMENTS)

        match_q = _create_rule_and_queue(ctx, ev, td, account, "match", subject)
        miss_q = _create_rule_and_queue(ctx, ev, td, account, "miss", other)

        task_def = ecs.register_task_definition(
            family=ctx.unique_name(_PREFIX + "td-"),
            networkMode="awsvpc",
            requiresCompatibilities=["FARGATE"],
            cpu="256",
            memory=_TASK_MEMORY,
            executionRoleArn=exec_role,
            containerDefinitions=[{
                "name": "app",
                "image": _BUSYBOX,
                "essential": True,
                # The container-level hard limit, deliberately BELOW the task's memory so the task
                # has headroom and this field is the only thing that can bite.
                "memory": _CONTAINER_MEMORY,
                "command": ["sh", "-c", "echo placeholder"],
                "logConfiguration": {"logDriver": "awslogs",
                                     "options": {"awslogs-group": log_group,
                                                 "awslogs-region": ctx.region,
                                                 "awslogs-stream-prefix": _STREAM_PREFIX}},
            }],
            tags=_ecs_tags())["taskDefinition"]["taskDefinitionArn"]
        td.add(f"ecs task definition {task_def}",
               lambda: (_swallow(lambda: ecs.deregister_task_definition(taskDefinition=task_def)),
                        _swallow(lambda: ecs.delete_task_definitions(
                            taskDefinitions=[task_def]))))

        net = {"awsvpcConfiguration": {"subnets": subnets[:1], "securityGroups": [sg],
                                       "assignPublicIp": "ENABLED"}}
        # awk string doubling from a 1 MiB seed: the victim's 10 doublings target 1 GiB and cannot
        # survive a 512 MiB container, the control's 4 target 16 MiB and must. The `&&` chaining is
        # what makes ALLOC_DONE's absence falsifiable -- awk has to exit 0 for it to print.
        victim = _run(ctx, ecs, td, subject, task_def, net, "victim", _ALLOC % 10)
        control = _run(ctx, ecs, td, subject, task_def, net, "control", _ALLOC % 4)
        victim = _await_stopped(ecs, subject, victim)
        control = _await_stopped(ecs, subject, control)

        # The ECS API's own view of the kill.
        vc = _container(victim)
        assert vc.get("exitCode") == 137, (
            f"an OOM-killed container must report exit code 137; got {vc!r} "
            f"stoppedReason={victim.get('stoppedReason')!r}")
        assert vc.get("reason") == _OOM_REASON, (
            f"the container's reason must be exactly {_OOM_REASON!r} -- a runtime that kills the "
            f"process with a bare exit 137 and no reason, or that reports Docker's OOMKilled "
            f"vocabulary instead of ECS's sentence, fails here; got {vc.get('reason')!r}")
        assert victim.get("stopCode") == "EssentialContainerExited", (
            f"the task must stop because its essential container exited, got "
            f"{victim.get('stopCode')!r}")
        assert victim.get("stoppedReason") == "Essential container in task exited", (
            f"stoppedReason must be exactly 'Essential container in task exited', got "
            f"{victim.get('stoppedReason')!r}")

        # The allocation really was interrupted mid-flight.
        v_log = _settled_lines(ctx, log_group, victim)
        assert any("ALLOC_START" in m for m in v_log), (
            f"the victim's own stdout must show it started allocating -- otherwise the kill is a "
            f"statement about the image or the log pipe; got {v_log!r}")
        assert not any("ALLOC_DONE" in m for m in v_log), (
            f"ALLOC_DONE means awk COMPLETED the 1 GiB allocation inside a 512 MiB container, so "
            f"the limit was not enforced; got {v_log!r}")
        assert not any("LEN=" in m for m in v_log), (
            f"LEN= is printed only after the final doubling succeeds; its presence means the "
            f"allocation was never interrupted; got {v_log!r}")

        # Control: the same command, image and log path at 16 MiB.
        cc = _container(control)
        assert cc.get("exitCode") == 0, (
            f"the under-limit control task must exit 0, got {cc!r} "
            f"stoppedReason={control.get('stoppedReason')!r}")
        assert cc.get("reason") is None, (
            f"a container that was not killed must carry NO reason, got {cc.get('reason')!r}")
        c_log = _settled_lines(ctx, log_group, control)
        assert any("ALLOC_START" in m for m in c_log), c_log
        assert any(f"LEN={_CONTROL_BYTES}" in m for m in c_log), (
            f"the control must report exactly {_CONTROL_BYTES} allocated bytes, proving the awk "
            f"form really allocates what it claims; got {c_log!r}")
        assert any("ALLOC_DONE" in m for m in c_log), (
            f"the control is the barrier that makes ALLOC_DONE's absence in the victim meaningful; "
            f"got {c_log!r}")

        # The same reason string inside the EventBridge detail. EventBridge is at-least-once and ECS
        # can emit more than one STOPPED event per task, so every event is checked, not a count.
        events = _drain_until(ctx, match_q, {victim["taskArn"], control["taskArn"]})
        v_events = events.get(victim["taskArn"], [])
        assert v_events, (
            f"at least one ECS Task State Change event with lastStatus STOPPED must be delivered "
            f"for the victim task; the queue yielded events for {sorted(events)!r}")
        for detail in v_events:
            evc = (detail.get("containers") or [{}])[0]
            assert evc.get("exitCode") == 137, (
                f"the event body must carry the container's real exit code, got {evc!r}")
            assert evc.get("reason") == _OOM_REASON, (
                f"the SAME reason string must appear in the event detail as on DescribeTasks -- "
                f"this cross-surface agreement is the property no recorded response can fake; got "
                f"{evc.get('reason')!r} against {_OOM_REASON!r}")
            assert detail.get("stopCode") == "EssentialContainerExited", detail
            assert detail.get("lastStatus") == "STOPPED", detail
        for detail in events.get(control["taskArn"], []):
            evc = (detail.get("containers") or [{}])[0]
            assert evc.get("exitCode") == 0, (
                f"the control's event must carry ITS own exit code, not the victim's -- an "
                f"emulator stamping every event with one body fails here; got {evc!r}")
            assert "reason" not in evc, (
                f"the control's event must carry no container reason at all, got {evc!r}")
        assert events.get(control["taskArn"]), (
            f"the control task's STOPPED event is the delivery control for the absence asserted "
            f"below; got events for {sorted(events)!r}")

        # Effect absent: an identical rule scoped to the other cluster gets nothing.
        stray = _drain_window(ctx, miss_q, _ABSENCE_WINDOW_S)
        assert not stray, (
            f"a rule whose ONLY difference is detail.clusterArn must receive nothing for these "
            f"tasks; it received {stray!r}")

        vol = ecs.describe_task_definition(taskDefinition=task_def)["taskDefinition"]
        assert vol["containerDefinitions"][0]["memory"] == _CONTAINER_MEMORY, vol
        assert vol["memory"] == _TASK_MEMORY, (
            f"the TASK had {_TASK_MEMORY} MiB of headroom, so the container-level "
            f"{_CONTAINER_MEMORY} MiB limit is the only thing that can have killed it; got "
            f"{vol['memory']!r}")
        ok = True
    finally:
        # Teardown runs inline: the ENI drain outlasts the bounded cleanup window.
        leaks = td.run()
        if ok:
            assert not leaks, f"verified teardown did not remove everything: {leaks!r}"
        elif leaks:
            print(f"teardown after a failing body: {leaks!r}", file=sys.stderr)


_PREFIX = "sim2real-xsvc-oom-"
_MANAGED_TAGS = {
    "sim2real:managed": "true",
    "sim2real:prefix": "sim2real-xsvc",
    "sim2real": "ecs-oom-eventbridge",
}

# The exact Fargate OOM reason; note the lower-case "container".
_OOM_REASON = "OutOfMemoryError: container killed due to memory usage"

_TASK_MEMORY = "1024"
_CONTAINER_MEMORY = 512
_CONTROL_BYTES = 16777216   # 1 MiB seed doubled 4 times

_ALLOC = ('echo ALLOC_START; awk \'BEGIN{s=sprintf("%%1048576s","");'
          'for(i=0;i<%d;i++){s=s s}print "LEN=" length(s)}\' && echo ALLOC_DONE')

# Bounded deadlines, each with its reason.
_TASK_TIMEOUT_S = 900        # Fargate placement + public-ECR pull + the allocation + the kill
_LOG_TIMEOUT_S = 420         # awslogs stream creation, then event delivery, then convergence
_EVENT_TIMEOUT_S = 600       # ECS -> EventBridge -> SQS fan-out for a STOPPED state change
_ABSENCE_WINDOW_S = 90       # bounded settle window for the effect-absent queue
_TEARDOWN_TIMEOUT_S = 300    # deleted -> polled actually gone, per resource

_BUSYBOX = ("public.ecr.aws/docker/library/busybox"
            "@sha256:73aaf090f3d85aa34ee199857f03fa3a95c8ede2ffd4cc2cdb5b94e566b11662")
_STREAM_PREFIX = "oom"

_ECS_TASKS_TRUST = {
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow", "Principal": {"Service": "ecs-tasks.amazonaws.com"},
                   "Action": "sts:AssumeRole"}],
}
_EXEC_STATEMENTS = [
    {"Effect": "Allow",
     "Action": ["ecr:GetAuthorizationToken", "ecr:BatchCheckLayerAvailability",
                "ecr:GetDownloadUrlForLayer", "ecr:BatchGetImage",
                "logs:CreateLogStream", "logs:PutLogEvents"],
     "Resource": "*"}
]


class _Teardown:
    """Every undo, run inline in reverse creation order and also registered with ctx.on_cleanup
    as the failure-path net; inline because the ENI drain outlasts the bounded cleanup window."""

    def __init__(self, ctx):
        self._ctx = ctx
        self._steps = []

    def add(self, label, fn):
        self._steps.append((label, fn))
        self._ctx.on_cleanup(fn)

    def run(self):
        leaks = []
        for label, fn in reversed(self._steps):
            try:
                fn()
            except Exception as exc:  # noqa: BLE001 - collected, not swallowed
                leaks.append(f"{label}: {exc!r}")
        return leaks


def _ecs_tags():
    return [{"key": k, "value": v} for k, v in _MANAGED_TAGS.items()]


def _kv_tags():
    return [{"Key": k, "Value": v} for k, v in _MANAGED_TAGS.items()]


def _swallow(fn):
    try:
        fn()
    except Exception:  # noqa: BLE001 - best-effort teardown step
        pass


def _safe(fn):
    try:
        return fn()
    except Exception:  # noqa: BLE001 - probe
        return None


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=1.0, description="condition"):
    """Poll probe() until predicate(result); return the final result. Raises on a deadline miss."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _fargate_network(ctx):
    """(subnets, security group) for Fargate (awsvpc) tasks from the run's shared network."""
    net = ctx.network()
    return list(net.subnet_ids), net.security_group_id


def _settle(probe, *, reads, interval_s, timeout_s, description):
    """`probe()` must succeed `reads` times in a row before the deadline; IAM exposes no
    "propagated" condition, so repeated success is the observable proxy."""
    deadline = time.monotonic() + timeout_s
    good = 0
    while time.monotonic() < deadline:
        good = good + 1 if probe() else 0
        if good >= reads:
            return
        time.sleep(interval_s)
    raise AssertionError(f"{description} did not settle within {timeout_s}s "
                         f"({good}/{reads} consecutive good reads)")


def _ensure_ecs_slr(ctx):
    """Create AWSServiceRoleForECS, which RunTask (unlike CreateService) does not create implicitly.

    Not torn down: the role is account-level and shared.
    """
    iam = ctx.client("iam")
    try:
        iam.create_service_linked_role(AWSServiceName="ecs.amazonaws.com")
    except ClientError as exc:
        error = exc.response["Error"]
        # The role already exists: IAM refuses the name as taken.
        taken = (
            "Service role name AWSServiceRoleForECS has been taken in this account, please try a "
            "different suffix."
        )
        if (error["Code"], error.get("Message")) != ("InvalidInput", taken):
            raise AssertionError(f"cannot create the ECS service-linked role: {exc}") from exc
        return
    _settle(lambda: _safe(lambda: iam.get_role(RoleName="AWSServiceRoleForECS")) is not None,
            reads=3, interval_s=5.0, timeout_s=60.0,
            description="freshly created AWSServiceRoleForECS visible via GetRole")


def _iam_role(ctx, td, kind, statements):
    """A fresh role trusting ecs-tasks with one inline policy; returns (name, arn)."""
    iam = ctx.client("iam")
    name = ctx.unique_name(_PREFIX + kind + "-")
    arn = iam.create_role(
        RoleName=name, AssumeRolePolicyDocument=json.dumps(_ECS_TASKS_TRUST), Path="/sim2real/",
        Description="SimParity behavioral: ECS OOM " + kind, Tags=_kv_tags())["Role"]["Arn"]

    def _drop():
        _swallow(lambda: iam.delete_role_policy(RoleName=name, PolicyName="inline"))
        _swallow(lambda: iam.delete_role(RoleName=name))
        if _safe(lambda: iam.get_role(RoleName=name)) is not None:
            raise AssertionError(f"IAM role {name} still exists after DeleteRole")

    td.add(f"iam role {name}", _drop)
    iam.put_role_policy(RoleName=name, PolicyName="inline",
                        PolicyDocument=json.dumps({"Version": "2012-10-17",
                                                   "Statement": statements}))
    _poll_until(lambda: _safe(lambda: iam.get_role_policy(RoleName=name, PolicyName="inline")),
                lambda r: r is not None, timeout_s=60, interval_s=2,
                description=f"role {name} inline policy readable")
    _settle(lambda: _safe(lambda: iam.get_role_policy(
                RoleName=name, PolicyName="inline")) is not None,
            reads=3, interval_s=5.0, timeout_s=60.0,
            description=f"role {name} inline policy read-back")
    return name, arn


def _create_cluster(ctx, ecs, td, kind):
    name = ctx.unique_name(_PREFIX + kind + "-")
    ecs.create_cluster(clusterName=name, tags=_ecs_tags())

    def _drop():
        _swallow(lambda: ecs.delete_cluster(cluster=name))
        left = _safe(lambda: ecs.describe_clusters(clusters=[name]))
        for c in (left or {}).get("clusters", []):
            if c.get("status") not in ("INACTIVE", None):
                raise AssertionError(f"ECS cluster {name} still {c.get('status')!r} after "
                                     f"DeleteCluster")

    td.add(f"ecs cluster {name}", _drop)
    return name


def _create_log_group(ctx, td):
    """A log group this check owns outright, so teardown is one call that takes the streams too."""
    logs = ctx.client("logs")
    name = ctx.unique_name(_PREFIX + "lg-")
    logs.create_log_group(logGroupName=name, tags=dict(_MANAGED_TAGS))

    def _drop():
        _swallow(lambda: logs.delete_log_group(logGroupName=name))
        left = _safe(lambda: logs.describe_log_groups(logGroupNamePrefix=name))
        if left and left.get("logGroups"):
            raise AssertionError(f"log group {name} still present after DeleteLogGroup")

    td.add(f"log group {name}", _drop)
    return name


def _create_rule_and_queue(ctx, ev, td, account, kind, cluster_name):
    """An SQS queue plus a default-bus EventBridge rule targeting it; returns the queue URL.

    The queue policy is scoped to this rule's ARN, so the two rules cannot cross-deliver.
    """
    sqs = ctx.client("sqs")
    q_name = ctx.unique_name(_PREFIX + kind + "-q-")
    q_url = sqs.create_queue(QueueName=q_name, tags=dict(_MANAGED_TAGS))["QueueUrl"]

    def _drop_q():
        _swallow(lambda: sqs.delete_queue(QueueUrl=q_url))
        if _safe(lambda: sqs.get_queue_url(QueueName=q_name)) is not None:
            raise AssertionError(f"SQS queue {q_name} still resolvable after DeleteQueue")

    td.add(f"sqs queue {q_name}", _drop_q)
    q_arn = sqs.get_queue_attributes(QueueUrl=q_url, AttributeNames=["QueueArn"])[
        "Attributes"]["QueueArn"]

    rule = ctx.unique_name(_PREFIX + kind + "-rule-")
    cluster_arn = f"arn:aws:ecs:{ctx.region}:{account}:cluster/{cluster_name}"
    rule_arn = ev.put_rule(
        Name=rule, State="ENABLED", Tags=_kv_tags(),
        Description="SimParity behavioral: ECS Task State Change -> SQS",
        EventPattern=json.dumps({"source": ["aws.ecs"],
                                 "detail-type": ["ECS Task State Change"],
                                 "detail": {"clusterArn": [cluster_arn],
                                            "lastStatus": ["STOPPED"]}}))["RuleArn"]

    def _drop_rule():
        _swallow(lambda: ev.remove_targets(Rule=rule, Ids=["q"]))
        _swallow(lambda: ev.delete_rule(Name=rule))
        left = _safe(lambda: ev.describe_rule(Name=rule))
        if left is not None:
            raise AssertionError(f"EventBridge rule {rule} still present after DeleteRule")

    td.add(f"events rule {rule}", _drop_rule)
    sqs.set_queue_attributes(QueueUrl=q_url, Attributes={"Policy": json.dumps({
        "Version": "2012-10-17",
        "Statement": [{"Sid": "AllowEventBridge", "Effect": "Allow",
                       "Principal": {"Service": "events.amazonaws.com"},
                       "Action": "sqs:SendMessage", "Resource": q_arn,
                       "Condition": {"ArnEquals": {"aws:SourceArn": rule_arn}}}]})})
    ev.put_targets(Rule=rule, Targets=[{"Id": "q", "Arn": q_arn}])
    return q_url


def _run(ctx, ecs, td, cluster, task_def, net, label, command):
    resp = ecs.run_task(cluster=cluster, taskDefinition=task_def, launchType="FARGATE", count=1,
                        networkConfiguration=net, tags=_ecs_tags(),
                        overrides={"containerOverrides": [{"name": "app",
                                                           "command": ["sh", "-c", command]}]})
    assert not resp.get("failures"), (
        f"RunTask for the {label} task reported failures: {resp.get('failures')!r}")
    arn = resp["tasks"][0]["taskArn"]
    td.add(f"ecs task {arn}",
           lambda: _swallow(lambda: ecs.stop_task(cluster=cluster, task=arn,
                                                  reason="behavioral-cleanup")))
    return arn


def _await_stopped(ecs, cluster, arn):
    task = _poll_until(
        lambda: ecs.describe_tasks(cluster=cluster, tasks=[arn])["tasks"][0],
        lambda t: t["lastStatus"] == "STOPPED",
        timeout_s=_TASK_TIMEOUT_S, interval_s=10,
        description=f"task {arn} reaches STOPPED")
    assert task.get("stopCode") != "TaskFailedToStart", (
        f"the task never started, so nothing about the memory limit was measured: "
        f"stoppedReason={task.get('stoppedReason')!r} containers={task.get('containers')!r}")
    return task


def _container(task):
    return task["containers"][0]


def _log_messages(ctx, group, stream):
    logs = ctx.client("logs")
    out, token, seen = [], None, set()
    while True:
        kwargs = dict(logGroupName=group, logStreamName=stream, startFromHead=True)
        if token:
            kwargs["nextToken"] = token
        resp = _safe(lambda kw=dict(kwargs): logs.get_log_events(**kw))
        if resp is None:
            return out
        out.extend(e.get("message", "") for e in resp.get("events", []))
        token = resp.get("nextForwardToken")
        if not token or token in seen:
            return out
        seen.add(token)


def _settled_lines(ctx, group, task, stable_reads=3, interval_s=10):
    """Every line the task's container wrote, once the stream is stable across `stable_reads` reads.

    Logs offers no ingestion-complete signal, and asserting ALLOC_DONE is absent needs one.
    """
    stream = f"{_STREAM_PREFIX}/app/{task['taskArn'].rsplit('/', 1)[-1]}"
    last, stable = None, 0
    deadline = time.monotonic() + _LOG_TIMEOUT_S
    while time.monotonic() < deadline:
        msgs = _log_messages(ctx, group, stream)
        if msgs and last is not None and msgs == last:
            stable += 1
            if stable >= stable_reads:
                return msgs
        else:
            stable = 0
        last = msgs
        time.sleep(interval_s)
    raise AssertionError(f"log stream {group}/{stream} never settled within {_LOG_TIMEOUT_S}s; "
                         f"last read was {last!r}")


def _drain_until(ctx, queue_url, task_arns):
    """Every ECS Task State Change detail delivered for `task_arns`, keyed by taskArn.

    Long-polls until each wanted taskArn has at least one event.
    """
    sqs = ctx.client("sqs")
    found = {}
    deadline = time.monotonic() + _EVENT_TIMEOUT_S
    while time.monotonic() < deadline and set(found) < set(task_arns):
        resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=10,
                                   WaitTimeSeconds=20)
        for msg in resp.get("Messages", []):
            body = _safe(lambda m=msg: json.loads(m["Body"])) or {}
            detail = body.get("detail") or {}
            arn = detail.get("taskArn")
            if arn in task_arns:
                found.setdefault(arn, []).append(detail)
            _swallow(lambda m=msg: sqs.delete_message(QueueUrl=queue_url,
                                                      ReceiptHandle=m["ReceiptHandle"]))
    return found


def _drain_window(ctx, queue_url, window_s):
    """Every taskArn mentioned in anything the queue delivers over a bounded settle window."""
    sqs = ctx.client("sqs")
    seen = []
    deadline = time.monotonic() + window_s
    while time.monotonic() < deadline:
        resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=10,
                                   WaitTimeSeconds=20)
        for msg in resp.get("Messages", []):
            body = _safe(lambda m=msg: json.loads(m["Body"])) or {}
            seen.append((body.get("detail") or {}).get("taskArn"))
            _swallow(lambda m=msg: sqs.delete_message(QueueUrl=queue_url,
                                                      ReceiptHandle=m["ReceiptHandle"]))
    return seen


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
