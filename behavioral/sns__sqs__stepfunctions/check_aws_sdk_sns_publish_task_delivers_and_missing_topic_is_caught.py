"""aws-sdk-sns-publish-task-delivers-and-missing-topic-is-caught."""

from __future__ import annotations

import json
import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "aws-sdk-sns-publish-task-delivers-and-missing-topic-is-caught"
GROUP = "task_integrations"
SERVICES = ["sns", "sqs", "stepfunctions"]

#: The error an aws-sdk:sns:publish task reports for a topic ARN that names no topic: the
#: ASL error name and SNS's NotFound cause with the request id masked.
_MISSING_TOPIC = (
    "Sns.NotFoundException",
    "Topic does not exist (Service: Sns, Status Code: 404, Request ID: <id>) "
    "(SDK Attempt Count: 1)",
)


@tags(
    "axis:happy-path",
    "cap:c3",
    "concern:data-plane",
    "concern:eventing",
    "concern:negative-classes",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """An aws-sdk:sns:publish task delivers, and its missing-topic failure is catchable.

    The task returns SNS's MessageId and the message reaches a subscribed SQS queue; on a
    well-formed ARN naming no topic it fails with Sns.NotFoundException, which a Catch handles.
    """
    topic_arn = _create_topic(ctx)
    queue = _create_queue(ctx, topic_arn)
    _subscribe(ctx, topic_arn, queue)
    missing_topic_arn = topic_arn + "-absent"
    _, role_arn = _create_sfn_role(
        ctx,
        [
            {
                "Effect": "Allow",
                "Action": "sns:Publish",
                "Resource": [topic_arn, missing_topic_arn],
            },
        ],
    )
    sm_arn = _create_state_machine(ctx, role_arn)

    marker = ctx.unique_name("m-")
    ok = _run_to_terminal(ctx, sm_arn, {"topic": topic_arn, "message": marker})
    assert ok["status"] == "SUCCEEDED", (
        f"the publish task ended {ok['status']!r}: {ok.get('error')!r} {ok.get('cause')!r}"
    )
    ok_out = json.loads(ok["output"])
    assert "handled" not in ok_out and isinstance(ok_out.get("MessageId"), str), (
        f"the task output must be the Publish response carrying MessageId, got {ok_out!r}"
    )
    delivered = _receive_one(ctx, queue["url"])
    assert delivered.get("Message") == marker and delivered.get("TopicArn") == topic_arn, (
        f"the queue must receive the published message from the topic, got {delivered!r}"
    )
    assert delivered.get("MessageId") == ok_out["MessageId"], (
        f"the delivered MessageId {delivered.get('MessageId')!r} is not the task's "
        f"{ok_out['MessageId']!r}"
    )

    bad = _run_to_terminal(ctx, sm_arn, {"topic": missing_topic_arn, "message": "never"})
    assert bad["status"] == "SUCCEEDED", (
        f"the Catch on {_MISSING_TOPIC[0]!r} must handle the failure and end SUCCEEDED, got "
        f"{bad['status']!r}: error={bad.get('error')!r} cause={bad.get('cause')!r}"
    )
    bad_out = json.loads(bad["output"])
    assert bad_out.get("handled") == "missing-topic", f"the Missing state did not run: {bad_out!r}"
    err = bad_out.get("err") or {}
    got = (
        err.get("Error"),
        re.sub(r"Request ID: [0-9a-zA-Z-]+\)", "Request ID: <id>)", err.get("Cause") or ""),
    )
    assert got == _MISSING_TOPIC, f"the caught error was {err!r}, expected {_MISSING_TOPIC!r}"


# ===== helpers =====


def _budget_s(ctx, cap_s):
    """A wait's timeout: cap_s, capped by the runner's remaining time less 5 s."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _teardown(undo, *not_found: str):
    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _create_queue(ctx, topic_arn) -> dict:
    """A queue created with the policy that admits the topic, so it holds before any publish."""
    sqs = ctx.client("sqs")
    name = ctx.unique_name("sim2real-behav-q-")
    arn = f"arn:{topic_arn.split(':')[1]}:sqs:{ctx.region}:{ctx.account}:{name}"
    ctx.on_cleanup(
        _teardown(
            lambda: sqs.delete_queue(QueueUrl=sqs.get_queue_url(QueueName=name)["QueueUrl"]),
            "AWS.SimpleQueueService.NonExistentQueue",
            "QueueDoesNotExist",
        )
    )
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "sns.amazonaws.com"},
                "Action": "sqs:SendMessage",
                "Resource": arn,
                "Condition": {"ArnEquals": {"aws:SourceArn": topic_arn}},
            }
        ],
    }
    url = sqs.create_queue(
        QueueName=name, Attributes={"Policy": json.dumps(policy)}, tags={"sim2real": CHECK[:200]}
    )["QueueUrl"]
    return {"url": url, "arn": arn}


def _create_topic(ctx) -> str:
    sns = ctx.client("sns")
    name = ctx.unique_name("sim2real-behav-topic-")
    created = {}
    ctx.on_cleanup(lambda: created and sns.delete_topic(TopicArn=created["arn"]))
    created["arn"] = sns.create_topic(Name=name, Tags=[{"Key": "sim2real", "Value": CHECK[:200]}])[
        "TopicArn"
    ]
    return created["arn"]


def _subscribe(ctx, topic_arn, queue) -> None:
    sns = ctx.client("sns")
    sub = {}
    ctx.on_cleanup(_teardown(lambda: _unsubscribe(sns, sub), "NotFound"))
    sub["arn"] = sns.subscribe(
        TopicArn=topic_arn, Protocol="sqs", Endpoint=queue["arn"], ReturnSubscriptionArn=True
    )["SubscriptionArn"]


def _unsubscribe(sns, sub) -> None:
    """Teardown: remove the subscription once Subscribe has returned its ARN."""
    if "arn" in sub:
        sns.unsubscribe(SubscriptionArn=sub["arn"])


def _receive_one(ctx, queue_url, cap_s=30.0) -> dict:
    sqs = ctx.client("sqs")
    timeout_s = _budget_s(ctx, cap_s)
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        msgs = sqs.receive_message(
            QueueUrl=queue_url, MaxNumberOfMessages=1, WaitTimeSeconds=5
        ).get("Messages", [])
        if msgs:
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msgs[0]["ReceiptHandle"])
            return json.loads(msgs[0]["Body"])
    raise AssertionError(f"no message reached the subscribed queue within {timeout_s}s")


def _create_sfn_role(ctx, statements):
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-behav-role-")
    ctx.on_cleanup(_teardown(lambda: iam.delete_role(RoleName=name), "NoSuchEntity"))
    arn = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {"Service": "states.amazonaws.com"},
                        "Action": "sts:AssumeRole",
                    }
                ],
            }
        ),
        Tags=[{"Key": "sim2real", "Value": CHECK[:200]}],
    )["Role"]["Arn"]
    ctx.on_cleanup(
        _teardown(
            lambda: iam.delete_role_policy(RoleName=name, PolicyName="inline"), "NoSuchEntity"
        )
    )
    iam.put_role_policy(
        RoleName=name,
        PolicyName="inline",
        PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": statements}),
    )
    return name, arn


def _create_state_machine(ctx, role_arn):
    sfn = ctx.client("stepfunctions")
    name = ctx.unique_name("sim2real-behav-sm-")
    definition = {
        "Comment": "sim2real: one aws-sdk:sns:publish task with a Catch on the missing topic",
        "StartAt": "Publish",
        "States": {
            "Publish": {
                "Type": "Task",
                "Resource": f"arn:{role_arn.split(':')[1]}:states:::aws-sdk:sns:publish",
                "Parameters": {"TopicArn.$": "$.topic", "Message.$": "$.message"},
                "Catch": [
                    {"ErrorEquals": [_MISSING_TOPIC[0]], "ResultPath": "$.err", "Next": "Missing"}
                ],
                "End": True,
            },
            "Missing": {
                "Type": "Pass",
                "Parameters": {"handled": "missing-topic", "err.$": "$.err"},
                "End": True,
            },
        },
    }
    arn = f"arn:{role_arn.split(':')[1]}:states:{ctx.region}:{ctx.account}:stateMachine:{name}"
    ctx.on_cleanup(
        _teardown(lambda: sfn.delete_state_machine(stateMachineArn=arn), "StateMachineDoesNotExist")
    )
    deadline = time.monotonic() + _budget_s(ctx, 90.0)
    last = None
    while time.monotonic() < deadline:
        try:
            return sfn.create_state_machine(
                name=name,
                definition=json.dumps(definition),
                roleArn=role_arn,
                type="STANDARD",
                tags=[{"key": "sim2real", "value": CHECK[:200]}],
            )["stateMachineArn"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "AccessDeniedException":
                raise
            last = exc
            time.sleep(3)
    raise AssertionError(f"CreateStateMachine never stopped denying the fresh role: {last!r}")


_PROPAGATION_MARKERS = (
    "not authorized to assume",
    "cannot be assumed",
    "not authorized to perform",
    "AuthorizationError",
    "InvalidClientTokenId",
    "security token included in the request is invalid",
)


def _best_effort_stop(ctx, exec_arn):
    try:
        ctx.client("stepfunctions").stop_execution(
            executionArn=exec_arn, error="sim2real-cleanup", cause="cleanup"
        )
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ExecutionDoesNotExist":
            raise


def _wait_terminal(ctx, exec_arn, *, cap_s=60.0, interval_s=1.0):
    sfn = ctx.client("stepfunctions")
    timeout_s = _budget_s(ctx, cap_s)
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = sfn.describe_execution(executionArn=exec_arn)
        if last["status"] in ("SUCCEEDED", "FAILED", "TIMED_OUT", "ABORTED"):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"execution {exec_arn} was not terminal within {timeout_s}s: {last!r}")


def _run_to_terminal(ctx, sm_arn, input_data, *, propagation_s=90.0):
    """Retry only while the fresh role or its grant is still propagating.

    A FAILED execution naming authorization is retried; every other outcome is returned as is.
    """
    sfn = ctx.client("stepfunctions")
    retry_until = time.monotonic() + _budget_s(ctx, propagation_s)
    while True:
        exec_name = ctx.unique_name("sim2real-behav-exec-")
        exec_arn = sm_arn.replace(":stateMachine:", ":execution:", 1) + ":" + exec_name
        ctx.on_cleanup(lambda a=exec_arn: _best_effort_stop(ctx, a))
        sfn.start_execution(
            stateMachineArn=sm_arn,
            name=exec_name,
            input=json.dumps(input_data),
        )
        desc = _wait_terminal(ctx, exec_arn)
        blob = (desc.get("cause") or "") + (desc.get("error") or "")
        if desc["status"] != "FAILED" or not any(m in blob for m in _PROPAGATION_MARKERS):
            return desc
        if time.monotonic() >= retry_until:
            return desc
        time.sleep(3)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
