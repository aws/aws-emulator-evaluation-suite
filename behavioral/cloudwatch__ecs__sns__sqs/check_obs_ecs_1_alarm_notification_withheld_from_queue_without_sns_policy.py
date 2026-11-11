"""obs-ecs-1-alarm-notification-withheld-from-queue-without-sns-policy."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "obs-ecs-1-alarm-notification-withheld-from-queue-without-sns-policy"
GROUP = "alarm-notification"
SERVICES = ["cloudwatch", "ecs", "sns", "sqs"]

_EXTRA_GOOD_ROUNDS = 2


@tags("axis:negative-delivery", "concern:eventing", "concern:e2e", "dp:api", "plane:data", "cap:c1")
def run(ctx) -> None:
    """An alarm notification fanned via SNS never reaches an SQS queue lacking an SNS SendMessage
    grant while a granted sibling receives every round; once the grant is added, it receives.
    """
    ecs = ctx.client("ecs")
    cw = ctx.client("cloudwatch")
    sns = ctx.client("sns")
    sqs = ctx.client("sqs")

    # A Container-Insights cluster with a zero-task service: its RunningTaskCount is below 1
    # (or absent, which this alarm treats as breaching), so the alarm settles in ALARM on its own.
    cluster = ctx.unique_name("sim2real-xsvc-rtcneg-")
    ecs.create_cluster(clusterName=cluster,
                       settings=[{"name": "containerInsights", "value": "enabled"}],
                       tags=[{"key": "sim2real", "value": CHECK}])
    ctx.on_cleanup(lambda: _retry_cluster_delete(ecs, cluster))
    td = ecs.register_task_definition(
        family=ctx.unique_name("sim2real-xsvc-rtcneg-td-"), requiresCompatibilities=["EC2"],
        networkMode="bridge",
        containerDefinitions=[{"name": "app", "image": "public.ecr.aws/docker/library/busybox:1.36",
                               "memory": 64, "essential": True}],
    )["taskDefinition"]["taskDefinitionArn"]
    ctx.on_cleanup(lambda: _delete_task_definition(ecs, td))
    service = ctx.unique_name("sim2real-xsvc-rtcneg-svc-")
    ecs.create_service(cluster=cluster, serviceName=service, taskDefinition=td, desiredCount=0,
                       launchType="EC2", tags=[{"key": "sim2real", "value": CHECK}])
    ctx.on_cleanup(lambda: _delete_service(ecs, cluster, service))

    topic_arn = sns.create_topic(Name=ctx.unique_name("sim2real-xsvc-rtcneg-t-"),
                                 Tags=[{"Key": "sim2real", "Value": CHECK}])["TopicArn"]
    ctx.on_cleanup(lambda: sns.delete_topic(TopicArn=topic_arn))

    queues = {}
    for role in ("good", "bad"):
        url = sqs.create_queue(QueueName=ctx.unique_name(f"sim2real-xsvc-rtcneg-{role}-"),
                               tags={"sim2real": CHECK})["QueueUrl"]
        ctx.on_cleanup(lambda u=url: sqs.delete_queue(QueueUrl=u))
        arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
        queues[role] = (url, arn)
    good_url, good_arn = queues["good"]
    bad_url, bad_arn = queues["bad"]

    # Only the good queue grants SNS; the bad queue has no policy at all - the one defect.
    _grant(sqs, good_url, good_arn, topic_arn)
    for _, arn in queues.values():
        sub = sns.subscribe(TopicArn=topic_arn, Protocol="sqs", Endpoint=arn,
                            ReturnSubscriptionArn=True)["SubscriptionArn"]
        ctx.on_cleanup(lambda s=sub: _unsubscribe(sns, s))
    pol = sqs.get_queue_attributes(QueueUrl=bad_url, AttributeNames=["Policy"]).get("Attributes", {})
    assert "Policy" not in pol, f"the bad queue unexpectedly carries a policy: {pol!r}"

    alarm = ctx.unique_name("sim2real-xsvc-rtcneg-alarm-")
    cw.put_metric_alarm(
        AlarmName=alarm, AlarmDescription=f"sim2real {CHECK}", Namespace="ECS/ContainerInsights",
        MetricName="RunningTaskCount", Statistic="Maximum", Period=60, EvaluationPeriods=1,
        Threshold=1.0, ComparisonOperator="LessThanThreshold", TreatMissingData="breaching",
        Dimensions=[{"Name": "ClusterName", "Value": cluster},
                    {"Name": "ServiceName", "Value": service}],
        AlarmActions=[topic_arn], Tags=[{"Key": "sim2real", "Value": CHECK}])
    ctx.on_cleanup(lambda: cw.delete_alarms(AlarmNames=[alarm]))
    _poll_until(lambda: _alarm_state(cw, alarm), lambda s: s == "ALARM", timeout_s=420.0,
                interval_s=10.0, description=f"alarm {alarm} reaching ALARM for a zero-task service")

    def _round(token: str) -> None:
        """One OK->ALARM transition, tagged in its StateReason; fans to both queues at once."""
        cw.set_alarm_state(AlarmName=alarm, StateValue="OK", StateReason=f"sim2real reset {token}")
        cw.set_alarm_state(AlarmName=alarm, StateValue="ALARM", StateReason=f"sim2real round {token}")

    def _receive(url: str, token: str) -> dict | None:
        """One long-poll receive: the payload of round ``token`` if it arrived, else None."""
        for m in sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=10,
                                     WaitTimeSeconds=10).get("Messages", []):
            sqs.delete_message(QueueUrl=url, ReceiptHandle=m["ReceiptHandle"])
            payload = json.loads(json.loads(m["Body"])["Message"])
            if payload.get("NewStateReason", "").endswith(token):
                return payload
        return None

    def _wait_for(url: str, token: str, label: str) -> dict:
        return _poll_until(lambda: _receive(url, token), lambda p: p is not None,
                           timeout_s=180.0, interval_s=1.0,
                           description=f"round {token} arriving in the {label} queue")

    def _bad_depth() -> int:
        attrs = sqs.get_queue_attributes(QueueUrl=bad_url, AttributeNames=[
            "ApproximateNumberOfMessages", "ApproximateNumberOfMessagesNotVisible"])["Attributes"]
        return int(attrs["ApproximateNumberOfMessages"]) + int(attrs["ApproximateNumberOfMessagesNotVisible"])

    # Each round is one alarm transition fanned to both queues, so the good queue's arrival
    # bounds when the bad queue's copy would have landed; absence is proven without a sleep.
    for i in range(1 + _EXTRA_GOOD_ROUNDS):
        token = ctx.unique_name(f"r{i}-")
        _round(token)
        payload = _wait_for(good_url, token, "good")
        assert payload.get("AlarmName") == alarm and payload.get("NewStateValue") == "ALARM", (
            f"good-queue payload for round {token}: {payload!r}")
    stray = sqs.receive_message(QueueUrl=bad_url, MaxNumberOfMessages=10, WaitTimeSeconds=5).get("Messages", [])
    assert not stray, (
        f"the queue with no SNS grant received {len(stray)} notification(s) while the granted "
        f"queue received {1 + _EXTRA_GOOD_ROUNDS}: {[m['Body'][:200] for m in stray]!r}")
    assert _bad_depth() == 0, f"the queue with no SNS grant holds {_bad_depth()} message(s)"

    # Repair the one defect; the same queue must now receive a fresh round.
    _grant(sqs, bad_url, bad_arn, topic_arn)
    repaired = None
    deadline = time.monotonic() + 300.0
    while repaired is None and time.monotonic() < deadline:
        token = ctx.unique_name("fix-")
        _round(token)
        _wait_for(good_url, token, "good")
        # The grant may not have propagated for this round; when it does not arrive, fire another.
        round_end = time.monotonic() + 180.0
        while repaired is None and time.monotonic() < min(round_end, deadline):
            repaired = _receive(bad_url, token)
    assert repaired is not None, "the repaired queue never received a notification within 300s"
    assert repaired.get("AlarmName") == alarm, f"repaired-queue payload names {repaired.get('AlarmName')!r}"
    trigger = repaired.get("Trigger") or {}
    assert trigger.get("MetricName") == "RunningTaskCount", f"Trigger {trigger!r}"


def _grant(sqs, url: str, arn: str, topic_arn: str) -> None:
    sqs.set_queue_attributes(QueueUrl=url, Attributes={"Policy": json.dumps({
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "sns.amazonaws.com"},
                       "Action": "sqs:SendMessage", "Resource": arn,
                       "Condition": {"ArnEquals": {"aws:SourceArn": topic_arn}}}]})})


def _alarm_state(cw, name: str) -> str:
    return cw.describe_alarms(AlarmNames=[name], AlarmTypes=["MetricAlarm"])["MetricAlarms"][0]["StateValue"]


def _unsubscribe(sns, arn: str) -> None:
    try:
        sns.unsubscribe(SubscriptionArn=arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NotFound":
            raise


def _delete_service(ecs, cluster: str, service: str) -> None:
    try:
        ecs.delete_service(cluster=cluster, service=service, force=True)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in {"ServiceNotFoundException", "ServiceNotActiveException"}:
            raise


def _retry_cluster_delete(ecs, cluster: str) -> None:
    deadline = time.monotonic() + 120.0
    while True:
        try:
            ecs.delete_cluster(cluster=cluster)
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "ClusterNotFoundException":
                return
            if time.monotonic() > deadline:
                raise RuntimeError(f"ECS cluster {cluster}: {code}") from exc
            time.sleep(5.0)


def _delete_task_definition(ecs, td: str) -> None:
    """Deregister the revision if still ACTIVE, then delete it; an already-deleted one is fine."""
    try:
        status = ecs.describe_task_definition(taskDefinition=td)["taskDefinition"]["status"]
    except ClientError as exc:
        if "Unable to describe task definition" in exc.response["Error"].get("Message", ""):
            return
        raise
    if status == "DELETE_IN_PROGRESS":
        return
    if status == "ACTIVE":
        ecs.deregister_task_definition(taskDefinition=td)
    failures = ecs.delete_task_definitions(taskDefinitions=[td]).get("failures", [])
    if failures:
        raise RuntimeError(f"task definition {td} teardown failed: {failures}")


def _poll_until(probe, predicate, *, timeout_s, interval_s, description):
    deadline = time.monotonic() + timeout_s
    last = None
    delay = interval_s
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(delay)
        delay = min(delay * 1.5, 30.0)
    raise AssertionError(f"{description} did not happen within {timeout_s}s; last read {last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
