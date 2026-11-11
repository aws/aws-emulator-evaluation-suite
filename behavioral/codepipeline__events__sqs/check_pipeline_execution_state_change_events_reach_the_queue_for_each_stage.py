"""pipeline-execution-state-change-events-reach-the-queue-for-each-stage."""
from __future__ import annotations

import io
import json
import os
import time
import zipfile

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "pipeline-execution-state-change-events-reach-the-queue-for-each-stage"
GROUP = "event-propagation"
SERVICES = ["codepipeline", "events", "sqs"]

_TERMINAL = ("Succeeded", "Failed", "Stopped", "Cancelled", "Superseded")
_SCENARIO = "codepipeline-execution-state-change-events"
_ABSENCE_WINDOW_S = 10.0


@tags("axis:negative-delivery", "cap:c4", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """An EventBridge rule scoped to one pipeline delivers pipeline- and stage-level STARTED and
    SUCCEEDED events to SQS, attributed to that pipeline and execution and in stage order, while a
    concurrently-running unmatched twin pipeline delivers nothing and the queue drains to zero.

    Reference: https://docs.aws.amazon.com/eventbridge/latest/ref/events-ref-codepipeline.html
    Reference: https://docs.aws.amazon.com/codepipeline/latest/userguide/detect-state-changes-cloudwatch-events.html
    """
    cp = ctx.client("codepipeline")
    s3 = ctx.client("s3")
    sqs = ctx.client("sqs")
    eb = ctx.client("events")
    create_timeout_s = 240
    run_timeout_s = 300

    account = ctx.client("sts").get_caller_identity()["Account"]

    bucket = _artifact_bucket(ctx, s3)
    s3.put_object(Bucket=bucket, Key="source.zip", Body=_zip({"payload.bin": os.urandom(1024)}))
    role_arn = _pipeline_role(ctx, bucket)

    graded_name = ctx.unique_name("sim2real-behav-cpev-")
    twin_name = ctx.unique_name("sim2real-behav-cpevx-")
    graded_arn = f"arn:aws:codepipeline:{ctx.region}:{account}:{graded_name}"

    queue_url, queue_arn = _queue(ctx, sqs)

    # The rule matches ONLY the graded pipeline, so the twin is a genuine filter control.
    rule_name = ctx.unique_name("sim2real-behav-cpev-")
    eb.put_rule(
        Name=rule_name,
        EventPattern=json.dumps({
            "source": ["aws.codepipeline"],
            "detail-type": ["CodePipeline Pipeline Execution State Change",
                            "CodePipeline Stage Execution State Change"],
            "detail": {"pipeline": [graded_name]},
        }),
        State="ENABLED",
        Description=_SCENARIO,
        Tags=[{"Key": "sim2real", "Value": _SCENARIO}],
    )
    ctx.on_cleanup(lambda: eb.delete_rule(Name=rule_name, Force=True))
    eb.put_targets(Rule=rule_name, Targets=[{"Id": "queue", "Arn": queue_arn}])
    ctx.on_cleanup(lambda: eb.remove_targets(Rule=rule_name, Ids=["queue"], Force=True))
    _allow_eventbridge_to_send(sqs, queue_url, queue_arn,
                               f"arn:aws:events:{ctx.region}:{account}:rule/{rule_name}")

    for name in (graded_name, twin_name):
        _create_with_role_propagation(
            ctx, cp, _pipeline(name, role_arn, bucket, f"{name}/out.zip"),
            timeout_s=_budget_s(ctx, create_timeout_s))
        ctx.on_cleanup(lambda n=name: cp.delete_pipeline(name=n))

    graded_exec = _first_execution(ctx, cp, graded_name, timeout_s=_budget_s(ctx, run_timeout_s))
    twin_exec = _first_execution(ctx, cp, twin_name, timeout_s=_budget_s(ctx, run_timeout_s))
    ctx.on_cleanup(lambda: _abandon(cp, graded_name, graded_exec))
    ctx.on_cleanup(lambda: _abandon(cp, twin_name, twin_exec))

    for name, exec_id in ((graded_name, graded_exec), (twin_name, twin_exec)):
        status = _poll(ctx, lambda n=name, e=exec_id: _execution_status(cp, n, e),
                       lambda s: s in _TERMINAL,
                       timeout_s=_budget_s(ctx, run_timeout_s), interval_s=1,
                       what=f"execution {exec_id} of {name!r} to reach a terminal status")
        assert status == "Succeeded", (
            f"both pipelines must Succeed so the full STARTED..SUCCEEDED event sequence is "
            f"produced; execution {exec_id} of {name!r} expected 'Succeeded', got {status!r}"
        )

    # EventBridge is at-least-once and best effort, so assert a SET of (kind, stage, state), not
    # exact counts. States are upper-cased before comparing.
    required = {
        ("pipeline", None, "STARTED"),
        ("pipeline", None, "SUCCEEDED"),
        ("stage", "Source", "STARTED"),
        ("stage", "Source", "SUCCEEDED"),
        ("stage", "Deploy", "STARTED"),
        ("stage", "Deploy", "SUCCEEDED"),
    }
    collected: dict[tuple, dict] = {}
    foreign: list[dict] = []
    collect_s = _budget_s(ctx, run_timeout_s)
    deadline = time.monotonic() + collect_s
    while not required <= set(collected):
        for envelope in _receive(sqs, queue_url):
            detail = envelope.get("detail") or {}
            if detail.get("pipeline") != graded_name:
                foreign.append(envelope)
                continue
            kind = ("pipeline" if envelope.get("detail-type", "").startswith(
                "CodePipeline Pipeline") else "stage")
            key = (kind, detail.get("stage") if kind == "stage" else None,
                   str(detail.get("state", "")).upper())
            collected.setdefault(key, envelope)
        if required <= set(collected):
            break
        if time.monotonic() >= deadline and _budget_spent(ctx):
            raise TimeoutError("the graded pipeline's execution state change events: the run budget ended first; not graded")
        assert time.monotonic() < deadline, (
            f"CodePipeline must publish pipeline- and stage-level execution state changes to "
            f"EventBridge: after {collect_s:.0f}s the queue is missing "
            f"{sorted(required - set(collected))!r}; received {sorted(collected)!r}. An emulator "
            f"that runs the pipeline correctly but publishes nothing fails exactly here."
        )
        time.sleep(1)

    # Every collected event must be attributed to THIS pipeline and THIS execution.
    for key, envelope in sorted(collected.items()):
        detail = envelope["detail"]
        assert detail.get("execution-id") == graded_exec, (
            f"event {key!r} must carry the graded execution id: expected {graded_exec!r}, got "
            f"{detail.get('execution-id')!r} in {envelope!r}"
        )
        assert envelope.get("source") == "aws.codepipeline", (
            f"event {key!r} must have source 'aws.codepipeline', got "
            f"{envelope.get('source')!r}"
        )
        assert envelope.get("resources") == [graded_arn], (
            f"event {key!r} must name exactly the pipeline ARN in resources: expected "
            f"[{graded_arn!r}], got {envelope.get('resources')!r}"
        )
        assert envelope.get("account") == account, (
            f"event {key!r} must carry the caller's account {account!r}, got "
            f"{envelope.get('account')!r}"
        )
        assert envelope.get("region") == ctx.region, (
            f"event {key!r} must carry region {ctx.region!r}, got {envelope.get('region')!r}"
        )

    # Envelope `time` has second granularity, so the ordering is non-strict.
    source_done = _event_time(collected[("stage", "Source", "SUCCEEDED")])
    deploy_start = _event_time(collected[("stage", "Deploy", "STARTED")])
    assert source_done <= deploy_start, (
        f"the Source stage must be reported SUCCEEDED no later than the Deploy stage is reported "
        f"STARTED: Source SUCCEEDED at {source_done!r}, Deploy STARTED at {deploy_start!r} "
        f"(envelope `time`, second granularity per H3)"
    )
    pipeline_start = _event_time(collected[("pipeline", None, "STARTED")])
    pipeline_done = _event_time(collected[("pipeline", None, "SUCCEEDED")])
    assert pipeline_start <= source_done <= pipeline_done, (
        f"the pipeline-level window must contain the stage events: pipeline STARTED "
        f"{pipeline_start!r}, Source SUCCEEDED {source_done!r}, pipeline SUCCEEDED "
        f"{pipeline_done!r}"
    )

    # Both pipelines ran concurrently, so the twin's events would arrive alongside the graded
    # ones collected above; a fixed window then catches stragglers.
    assert foreign == [], (
        f"the rule matches detail.pipeline == [{graded_name!r}] only, so no event from the twin "
        f"pipeline {twin_name!r} (execution {twin_exec}) may reach this queue; got "
        f"{[e.get('detail', {}).get('pipeline') for e in foreign]!r}"
    )
    window_s = _ABSENCE_WINDOW_S
    hold_deadline = time.monotonic() + window_s
    while time.monotonic() < hold_deadline:
        for envelope in _receive(sqs, queue_url):
            pipeline_named = (envelope.get("detail") or {}).get("pipeline")
            assert pipeline_named == graded_name, (
                f"during a {window_s:.0f}s window after the graded events arrived the queue must "
                f"receive nothing from the "
                f"unmatched twin: got an event for pipeline {pipeline_named!r}, expected only "
                f"{graded_name!r}. Without this leg, a target that forwards every event "
                f"regardless of the rule pattern would pass."
            )
        time.sleep(max(0.0, min(1.0, hold_deadline - time.monotonic())))

    # A second observable for the absence: every received message was deleted, so the queue's
    # own depth must drain to zero.
    depth = _poll(ctx, lambda: _queue_depth(sqs, queue_url), lambda d: d == 0,
                  timeout_s=_budget_s(ctx, 120), interval_s=1,
                  what=f"queue {queue_url!r} to report zero messages once every graded event has "
                       f"been consumed and the unmatched twin has contributed none")
    assert depth == 0, (
        f"after draining the graded pipeline's events, the queue must be empty -- a non-zero "
        f"depth means something else was delivered, most likely from the unmatched twin "
        f"{twin_name!r}: got {depth} message(s)"
    )


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _poll(ctx, fn, pred, *, timeout_s, interval_s, what):
    """Poll fn() until pred(value) holds; raise on timeout."""
    deadline = time.monotonic() + timeout_s
    val = fn()
    while not pred(val):
        if time.monotonic() >= deadline:
            if _budget_spent(ctx):
                raise TimeoutError(f"{what}: the run budget ended first; not graded")
            raise AssertionError(
                f"timed out after {timeout_s:.0f}s waiting for {what}; last observed value {val!r}"
            )
        time.sleep(interval_s)
        val = fn()
    return val


def _zip(entries) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for entry, body in entries.items():
            zf.writestr(entry, body)
    return buf.getvalue()


def _queue(ctx, sqs):
    name = ctx.unique_name("sim2real-behav-cpev-")
    url = sqs.create_queue(QueueName=name,
                           tags={"sim2real": _SCENARIO})["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])[
        "Attributes"]["QueueArn"]
    return url, arn


def _allow_eventbridge_to_send(sqs, queue_url, queue_arn, rule_arn) -> None:
    """Scoped to this one rule, so the queue does not become writable by every EventBridge rule in
    the account."""
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


def _receive(sqs, queue_url):
    """One long-poll batch, parsed as EventBridge envelopes and deleted so none is counted twice."""
    resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=10,
                               WaitTimeSeconds=2, VisibilityTimeout=60)
    out = []
    for msg in resp.get("Messages", []):
        out.append(json.loads(msg["Body"]))
        sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
    return out


def _queue_depth(sqs, queue_url) -> int:
    """Visible + in-flight message count; fails if SQS omits either attribute."""
    attrs = sqs.get_queue_attributes(
        QueueUrl=queue_url,
        AttributeNames=["ApproximateNumberOfMessages", "ApproximateNumberOfMessagesNotVisible"],
    )["Attributes"]
    for k in ("ApproximateNumberOfMessages", "ApproximateNumberOfMessagesNotVisible"):
        assert k in attrs, (
            f"SQS must report {k} for {queue_url!r}; got attributes {attrs!r}"
        )
    return (int(attrs["ApproximateNumberOfMessages"])
            + int(attrs["ApproximateNumberOfMessagesNotVisible"]))


def _event_time(envelope):
    """The envelope `time` string; fails if missing so ordering never compares empty strings."""
    t = envelope.get("time")
    assert t, f"every EventBridge envelope must carry a `time`; got {envelope!r}"
    return t


def _purge_bucket(s3, bucket) -> None:
    for page in s3.get_paginator("list_object_versions").paginate(Bucket=bucket):
        objs = [
            {"Key": v["Key"], "VersionId": v["VersionId"]}
            for v in list(page.get("Versions", [])) + list(page.get("DeleteMarkers", []))
        ]
        if objs:
            failed = s3.delete_objects(Bucket=bucket, Delete={"Objects": objs}).get("Errors")
            if failed:
                raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
    s3.delete_bucket(Bucket=bucket)


def _artifact_bucket(ctx, s3) -> str:
    bucket = ctx.unique_name("sim2real-behav-cpev-").lower()
    kw = {"Bucket": bucket}
    if ctx.region != "us-east-1":
        kw["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kw)
    ctx.on_cleanup(lambda: _purge_bucket(s3, bucket))
    s3.put_bucket_tagging(Bucket=bucket,
                          Tagging={"TagSet": [{"Key": "sim2real", "Value": _SCENARIO}]})
    s3.put_bucket_versioning(Bucket=bucket, VersioningConfiguration={"Status": "Enabled"})
    return bucket


def _pipeline_role(ctx, bucket) -> str:
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-behav-cpev-")
    iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Principal": {"Service": "codepipeline.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }],
        }),
        Tags=[{"Key": "sim2real", "Value": _SCENARIO}],
    )
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    iam.put_role_policy(
        RoleName=name, PolicyName="artifacts",
        PolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Action": ["s3:GetObject", "s3:GetObjectVersion", "s3:PutObject",
                           "s3:GetBucketVersioning", "s3:ListBucket"],
                "Resource": [f"arn:aws:s3:::{bucket}", f"arn:aws:s3:::{bucket}/*"],
            }],
        }),
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=name, PolicyName="artifacts"))
    return f"arn:aws:iam::{ctx.client('sts').get_caller_identity()['Account']}:role/{name}"


def _create_with_role_propagation(ctx, cp, declaration, *, timeout_s):
    """CreatePipeline, retried while it answers InvalidStructureException because the freshly
    created role is still propagating and cannot yet be assumed."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return cp.create_pipeline(pipeline=declaration)
        except ClientError as exc:
            err = exc.response.get("Error", {})
            transient = (err.get("Code") == "InvalidStructureException"
                         and "AssumeRole" in err.get("Message", ""))
            if not transient or time.monotonic() >= deadline:
                if transient and _budget_spent(ctx):
                    raise TimeoutError("CreatePipeline past the role's propagation: the run budget ended first; not graded") from exc
                raise
            time.sleep(2)


def _pipeline(name, role_arn, bucket, object_key):
    """Source(S3) -> Deploy(S3): two stages, so there are two stage-level event pairs to observe
    and an order between them."""
    return {
        "name": name,
        "roleArn": role_arn,
        "artifactStore": {"type": "S3", "location": bucket},
        "pipelineType": "V2",
        "executionMode": "QUEUED",
        "stages": [
            {"name": "Source", "actions": [{
                "name": "Source",
                "actionTypeId": {"category": "Source", "owner": "AWS", "provider": "S3",
                                 "version": "1"},
                "runOrder": 1,
                "configuration": {"S3Bucket": bucket, "S3ObjectKey": "source.zip",
                                  "PollForSourceChanges": "false"},
                "outputArtifacts": [{"name": "SourceOutput"}],
            }]},
            {"name": "Deploy", "actions": [{
                "name": "Deploy",
                "actionTypeId": {"category": "Deploy", "owner": "AWS", "provider": "S3",
                                 "version": "1"},
                "runOrder": 1,
                "configuration": {"BucketName": bucket, "Extract": "false",
                                  "ObjectKey": object_key},
                "inputArtifacts": [{"name": "SourceOutput"}],
            }]},
        ],
    }


def _execution_status(cp, name, execution_id):
    try:
        return cp.get_pipeline_execution(
            pipelineName=name, pipelineExecutionId=execution_id)["pipelineExecution"]["status"]
    except ClientError:
        return None


def _execution_ids(cp, name):
    ids = []
    for page in cp.get_paginator("list_pipeline_executions").paginate(pipelineName=name):
        ids.extend(s["pipelineExecutionId"] for s in page.get("pipelineExecutionSummaries", []))
    return ids


def _first_execution(ctx, cp, name, *, timeout_s):
    ids = _poll(ctx, lambda: _execution_ids(cp, name), lambda i: len(i) >= 1,
                timeout_s=timeout_s, interval_s=1,
                what=f"CreatePipeline to auto-start an execution of {name!r}")
    return ids[0]


def _abandon(cp, name, execution_id):
    try:
        cp.stop_pipeline_execution(
            pipelineName=name, pipelineExecutionId=execution_id, abandon=True,
            reason="sim2real behavioral check teardown")
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        if code == "PipelineNotFoundException":
            return
        if code != "PipelineExecutionNotStoppableException":
            raise
        # Not stoppable is the outcome teardown wants only when the execution has already ended.
        status = cp.get_pipeline_execution(
            pipelineName=name, pipelineExecutionId=execution_id)["pipelineExecution"]["status"]
        if status not in ("Succeeded", "Failed", "Stopped", "Stopping", "Superseded", "Cancelled"):
            raise RuntimeError(f"execution {execution_id} of {name} was not stopped: {status}") from exc


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
