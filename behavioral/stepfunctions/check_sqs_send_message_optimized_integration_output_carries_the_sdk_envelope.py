"""sqs-send-message-optimized-integration-output-carries-the-sdk-envelope."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "sqs-send-message-optimized-integration-output-carries-the-sdk-envelope"
GROUP = "task_integrations"
SERVICES = ["stepfunctions", "sqs"]


def _assert_envelope(label: str, out: dict) -> None:
    """The optimized-integration SDK envelope: HTTP status/headers plus a response RequestId."""
    missing = {"SdkHttpMetadata", "SdkResponseMetadata"} - set(out)
    assert not missing, f"{label} output lacks {sorted(missing)!r}: {out!r}"
    http = out["SdkHttpMetadata"]
    assert http.get("HttpStatusCode") == 200, (
        f"{label} SdkHttpMetadata.HttpStatusCode was {http.get('HttpStatusCode')!r}"
    )
    headers = http.get("HttpHeaders")
    assert isinstance(headers, dict) and headers and all(
        isinstance(k, str) and isinstance(v, str) for k, v in headers.items()
    ), f"{label} SdkHttpMetadata.HttpHeaders was {headers!r}, expected a non-empty str->str map"
    all_headers = http.get("AllHttpHeaders")
    assert isinstance(all_headers, dict) and all_headers and all(
        isinstance(k, str) and isinstance(v, list) and all(isinstance(x, str) for x in v)
        for k, v in all_headers.items()
    ), f"{label} SdkHttpMetadata.AllHttpHeaders was {all_headers!r}, expected str->[str] map"
    req_id = out["SdkResponseMetadata"].get("RequestId")
    assert isinstance(req_id, str) and req_id, (
        f"{label} SdkResponseMetadata.RequestId was {req_id!r}"
    )


@tags("axis:happy-path", "cap:c3", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """A plain sqs:sendMessage task's TaskSucceeded output, and a sqs:sendMessage.waitForTaskToken
    task's TaskSubmitted output, both carry the SdkHttpMetadata/SdkResponseMetadata envelope.
    """

    queue = _create_queue(ctx)
    role_arn = _create_sfn_role(ctx, queue["arn"])
    sm_arn = _create_state_machine(ctx, queue["url"], role_arn)

    exec_arn, desc = _run_to_success(ctx, sm_arn, queue["url"])

    history = _history(ctx, exec_arn)
    succeeded = [e["taskSucceededEventDetails"] for e in history if e["type"] == "TaskSucceeded"
                 and e["taskSucceededEventDetails"]["resource"] == "sendMessage"]
    assert len(succeeded) == 1, f"expected one plain-sendMessage TaskSucceeded event, got {succeeded!r}"
    plain_out = json.loads(succeeded[0]["output"])
    _assert_envelope("the plain sqs:sendMessage TaskSucceeded", plain_out)

    submitted = [e["taskSubmittedEventDetails"] for e in history if e["type"] == "TaskSubmitted"]
    assert len(submitted) == 1, f"expected one TaskSubmitted event, got {submitted!r}"
    assert submitted[0]["resource"] == "sendMessage.waitForTaskToken", (
        f"TaskSubmitted resource was {submitted[0]['resource']!r}"
    )
    token_out = json.loads(submitted[0]["output"])
    _assert_envelope("the sqs:sendMessage.waitForTaskToken TaskSubmitted", token_out)

    assert plain_out["MessageId"] != token_out["MessageId"], (
        "the two sendMessage calls must be distinct deliveries, got the same MessageId "
        f"{plain_out['MessageId']!r}"
    )


# ===== helpers =====

def _teardown(undo, *not_found: str):
    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _create_queue(ctx) -> dict:
    sqs = ctx.client("sqs")
    name = ctx.unique_name("sim2real-behav-q-")
    url = sqs.create_queue(
        QueueName=name, tags={"sim2real": CHECK[:200]},
    )["QueueUrl"]
    ctx.on_cleanup(_teardown(
        lambda: sqs.delete_queue(QueueUrl=url), "AWS.SimpleQueueService.NonExistentQueue"))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    return {"url": url, "arn": arn}


def _create_role(ctx, trust_service, statements):
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-behav-role-")
    arn = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Principal": {"Service": trust_service},
                           "Action": "sts:AssumeRole"}],
        }),
        Tags=[{"Key": "sim2real", "Value": CHECK[:200]}],
    )["Role"]["Arn"]
    ctx.on_cleanup(_teardown(lambda: iam.delete_role(RoleName=name), "NoSuchEntity"))
    iam.put_role_policy(
        RoleName=name, PolicyName="inline",
        PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": statements}),
    )
    ctx.on_cleanup(_teardown(
        lambda: iam.delete_role_policy(RoleName=name, PolicyName="inline"), "NoSuchEntity"))
    return arn


def _create_sfn_role(ctx, queue_arn):
    return _create_role(ctx, "states.amazonaws.com", [
        {"Effect": "Allow", "Action": "sqs:SendMessage", "Resource": queue_arn},
    ])


def _create_state_machine(ctx, queue_url, role_arn):
    sfn = ctx.client("stepfunctions")
    name = ctx.unique_name("sim2real-behav-sm-")
    definition = {
        "Comment": "sim2real: a plain sqs:sendMessage, then a sqs:sendMessage.waitForTaskToken",
        "StartAt": "SendPlain",
        "States": {
            "SendPlain": {
                "Type": "Task",
                "Resource": "arn:aws:states:::sqs:sendMessage",
                "Parameters": {"QueueUrl": queue_url, "MessageBody": json.dumps({"plain": True})},
                "Next": "SendWithToken",
            },
            "SendWithToken": {
                "Type": "Task",
                "Resource": "arn:aws:states:::sqs:sendMessage.waitForTaskToken",
                "Parameters": {
                    "QueueUrl": queue_url,
                    "MessageBody": {"token.$": "$$.Task.Token"},
                },
                "TimeoutSeconds": 120,
                "End": True,
            },
        },
    }
    deadline = time.monotonic() + 90.0
    last = None
    while time.monotonic() < deadline:
        try:
            arn = sfn.create_state_machine(
                name=name, definition=json.dumps(definition), roleArn=role_arn,
                type="STANDARD", tags=[{"key": "sim2real", "value": CHECK[:200]}],
            )["stateMachineArn"]
            ctx.on_cleanup(_teardown(
                lambda: sfn.delete_state_machine(stateMachineArn=arn), "StateMachineDoesNotExist"))
            return arn
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "AccessDeniedException":
                raise
            last = exc
            time.sleep(3)
    raise AssertionError(f"CreateStateMachine never stopped denying the fresh role: {last!r}")


def _best_effort_stop(ctx, exec_arn):
    sfn = ctx.client("stepfunctions")
    try:
        sfn.stop_execution(executionArn=exec_arn, error="sim2real-cleanup", cause="cleanup")
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ExecutionDoesNotExist":
            raise


def _start(ctx, sm_arn):
    sfn = ctx.client("stepfunctions")
    arn = sfn.start_execution(
        stateMachineArn=sm_arn, name=ctx.unique_name("sim2real-behav-exec-"), input="{}",
    )["executionArn"]
    ctx.on_cleanup(lambda: _best_effort_stop(ctx, arn))
    return arn


def _history(ctx, exec_arn):
    sfn = ctx.client("stepfunctions")
    out, token = [], None
    while True:
        kwargs = {"executionArn": exec_arn, "maxResults": 200}
        if token:
            kwargs["nextToken"] = token
        resp = sfn.get_execution_history(**kwargs)
        out.extend(resp["events"])
        token = resp.get("nextToken")
        if not token:
            return out


_PROPAGATION_MARKERS = (
    "not authorized to assume",
    "cannot be assumed",
    "UnrecognizedClientException",
    "InvalidClientTokenId",
    "security token included in the request is invalid",
)


def _await_task_token(ctx, queue_url, exec_arn, *, timeout_s=60.0):
    """Poll the queue for the waitForTaskToken message (the SendPlain delivery arrives too) and
    return its embedded taskToken; also confirms the plain send actually landed in the queue.

    Returns None if the execution left RUNNING (its cause names whether that was propagation)."""
    sqs = ctx.client("sqs")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = sqs.receive_message(
            QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=5,
        )
        for m in resp.get("Messages", []):
            body = json.loads(m["Body"])
            if "token" in body:
                return body["token"]
        desc = ctx.client("stepfunctions").describe_execution(executionArn=exec_arn)
        if desc["status"] != "RUNNING":
            return None
    raise AssertionError(f"no task-token message arrived in {timeout_s}s")


def _run_to_success(ctx, sm_arn, queue_url, *, propagation_s=90.0):
    """Start executions until one's fresh role is usable, deliver the callback, run to terminal."""
    sfn = ctx.client("stepfunctions")
    retry_until = time.monotonic() + propagation_s
    while True:
        exec_arn = _start(ctx, sm_arn)
        token = _await_task_token(ctx, queue_url, exec_arn)
        if token is not None:
            sfn.send_task_success(taskToken=token, output=json.dumps({"ack": True}))
            desc = _wait_terminal(ctx, exec_arn)
            if desc["status"] == "SUCCEEDED":
                return exec_arn, desc
            blob = (desc.get("cause") or "") + (desc.get("error") or "")
        else:
            desc = ctx.client("stepfunctions").describe_execution(executionArn=exec_arn)
            blob = (desc.get("cause") or "") + (desc.get("error") or "")
        if not any(m in blob for m in _PROPAGATION_MARKERS) or time.monotonic() >= retry_until:
            raise AssertionError(
                f"execution ended {desc['status']!r}: {desc.get('error')!r} {desc.get('cause')!r}"
            )
        time.sleep(3)


def _wait_terminal(ctx, exec_arn, *, timeout_s=60.0, interval_s=1.0):
    sfn = ctx.client("stepfunctions")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = sfn.describe_execution(executionArn=exec_arn)
        if last["status"] in ("SUCCEEDED", "FAILED", "TIMED_OUT", "ABORTED"):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"execution {exec_arn} was not terminal within {timeout_s}s: {last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
