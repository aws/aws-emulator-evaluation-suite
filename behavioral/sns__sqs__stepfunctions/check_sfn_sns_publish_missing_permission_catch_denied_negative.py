"""sfn-sns-publish-missing-permission-catch-denied-negative."""

from __future__ import annotations

import json
import re
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "sfn-sns-publish-missing-permission-catch-denied-negative"

GROUP = "overly-permissive"

SERVICES = ["stepfunctions", "sns", "sqs"]

_TRUST_RACE_MARKERS = (
    "not authorized to assume",
    "cannot be assumed",
    "is not authorized to perform: sts:AssumeRole",
)

_DENIAL_MARKERS = ("accessdenied", "authorizationerror", "not authorized to perform")


def _run_to_terminal(sfn, sm_arn: str, input_str: str, *, timeout_s=60.0, interval_s=2.0):
    exec_arn = sfn.start_execution(stateMachineArn=sm_arn, input=input_str)["executionArn"]
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = sfn.describe_execution(executionArn=exec_arn)
        if last["status"] in ("SUCCEEDED", "FAILED", "TIMED_OUT", "ABORTED"):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"execution {exec_arn} was not terminal within {timeout_s}s: {last!r}")


def _run_until_publish_authorized(sfn, sm_arn: str, input_str: str, max_attempts: int = 8):
    """Start an execution, retrying while a just-attached grant has not reached the authorizer
    (a Catch output naming the denial); any other result is returned at once."""
    race_markers = _TRUST_RACE_MARKERS + _DENIAL_MARKERS
    desc = None
    for attempt in range(max_attempts):
        desc = _run_to_terminal(sfn, sm_arn, input_str, timeout_s=30.0, interval_s=3.0)
        history_types = [e["type"] for e in _history(sfn, desc["executionArn"])]
        if "TaskFailed" not in history_types:
            return desc, history_types
        blob = ((desc.get("cause") or "") + (desc.get("error") or "")).lower()
        taskfail_cause = _task_failed_cause(sfn, desc["executionArn"]).lower()
        if not any(m in blob or m in taskfail_cause for m in race_markers):
            return desc, history_types
        time.sleep(10 + attempt * 5)
    raise AssertionError(
        f"sns:Publish authorization did not propagate after {max_attempts} attempts "
        f"(last execution: {desc.get('executionArn') if desc else 'n/a'})"
    )


def _run_until_publish_denied(ctx, sfn, sm_arn: str, queue_url: str, prefix: str, max_attempts: int = 6):
    """Run until the revoked permission bites (authz propagation lags GetRolePolicy), retrying
    with backoff and a per-attempt message; returns ``(desc, history, message, earlier_messages)``.
    """
    desc = None
    history = None
    earlier: list[str] = []
    for attempt in range(max_attempts):
        message = f"{prefix}-{attempt}"
        desc = _run_to_terminal(sfn, sm_arn, json.dumps({"message": message}), timeout_s=30.0,
                                interval_s=3.0)
        history = _history(sfn, desc["executionArn"])
        types = [e["type"] for e in history]
        if "TaskFailed" in types:
            return desc, history, message, earlier
        earlier.append(message)
        _drain_queue(ctx, queue_url)
        time.sleep(5 + attempt * 5)
    raise AssertionError(
        f"sns:Publish still succeeded after {max_attempts} attempts following delete_role_policy; "
        "IAM authorization did not revoke within budget"
    )


def _drain_queue(ctx, queue_url: str) -> None:
    """Best-effort drain, used to clean up a stray delivery from a propagation-lag retry."""
    sqs = ctx.client("sqs")
    for _ in range(5):
        resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=1)
        msgs = resp.get("Messages", [])
        if not msgs:
            return
        for msg in msgs:
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])


def _history(sfn, exec_arn: str) -> list[dict]:
    out, token = [], None
    while True:
        kwargs: dict[str, Any] = {"executionArn": exec_arn, "maxResults": 200}
        if token:
            kwargs["nextToken"] = token
        resp = sfn.get_execution_history(**kwargs)
        out.extend(resp["events"])
        token = resp.get("nextToken")
        if not token:
            return out


def _task_failed_cause(sfn, exec_arn: str) -> str:
    for e in _history(sfn, exec_arn):
        if e["type"] == "TaskFailed":
            return e["taskFailedEventDetails"].get("cause") or ""
    return ""


@tags(
    "axis:rejection",
    "cap:c3",
    "concern:data-plane",
    "concern:e2e",
    "concern:eventing",
    "concern:negative-classes",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """An sns:publish Task delivers to a subscribed SQS queue; without sns:Publish it fails with
    SNS's AuthorizationError, is caught into a Denied state, and nothing is delivered. Restoring
    the permission makes the identical call deliver again.
    """
    topic = _create_topic(ctx)
    queue = _create_queue(ctx)
    _subscribe_queue_to_topic(ctx, topic, queue)

    sfn = ctx.client("stepfunctions")
    iam = ctx.client("iam")

    role_name = _xname(ctx, "sfnsns-role")
    trust = json.dumps(
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
    )
    role_arn = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=trust, Tags=_xsvc_tags_kv()
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: _delete_role(ctx, role_name))

    policy_name = "sns-publish"
    policy_doc = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Action": "sns:Publish", "Resource": topic["arn"]}
            ],
        }
    )

    def _grant() -> None:
        iam.put_role_policy(
            RoleName=role_name, PolicyName=policy_name, PolicyDocument=policy_doc
        )
        _poll_until(
            lambda: iam.get_role_policy(RoleName=role_name, PolicyName=policy_name),
            lambda r: "PolicyDocument" in r,
            timeout_s=30,
            interval_s=2,
            description="sns-publish policy readable",
        )

    def _revoke() -> None:
        iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name)

        def _absent() -> bool:
            try:
                iam.get_role_policy(RoleName=role_name, PolicyName=policy_name)
                return False
            except ClientError as e:
                if e.response["Error"]["Code"] == "NoSuchEntity":
                    return True
                raise

        _poll_until(
            _absent, lambda gone: gone, timeout_s=30, interval_s=2,
            description="sns-publish policy removed",
        )

    _grant()

    sm_name = _xname(ctx, "sfnsns-sm")
    definition = json.dumps(
        {
            "StartAt": "PublishToSNS",
            "States": {
                "PublishToSNS": {
                    "Type": "Task",
                    "Resource": "arn:aws:states:::sns:publish",
                    "Parameters": {"TopicArn": topic["arn"], "Message.$": "$.message"},
                    "Catch": [
                        {
                            "ErrorEquals": ["States.ALL"],
                            "Next": "Denied",
                            "ResultPath": "$.errorInfo",
                        }
                    ],
                    "End": True,
                },
                "Denied": {
                    "Type": "Pass",
                    "Parameters": {"handled": "denied", "errorInfo.$": "$.errorInfo"},
                    "End": True,
                },
            },
        }
    )
    sm_arn = sfn.create_state_machine(
        name=sm_name, definition=definition, roleArn=role_arn, tags=_xsvc_tags_lower()
    )["stateMachineArn"]
    ctx.on_cleanup(lambda: sfn.delete_state_machine(stateMachineArn=sm_arn))

    # Beat 1 — positive control: with sns:Publish granted, the Task succeeds directly (the
    # Catch never fires) and the message is delivered to the subscribed queue.
    good, good_types = _run_until_publish_authorized(
        sfn, sm_arn, json.dumps({"message": "control-positive"})
    )
    assert good["status"] == "SUCCEEDED", (
        f"Positive control expected SUCCEEDED, got: {good['status']!r}"
    )
    assert "TaskFailed" not in good_types, (
        f"Positive control's Task failed and was caught; history types: {good_types!r}"
    )
    good_msgs = _wait_for_messages(ctx, queue["url"], expected_count=1, timeout_s=30)
    good_envelope = good_msgs[0]["body"]
    assert good_envelope["Message"] == "control-positive", (
        f"Expected delivered envelope Message 'control-positive', got: {good_envelope.get('Message')!r}"
    )
    # The positive leg's delivery latency, execution start to SQS enqueue, bounds the absence
    # window below.
    latency_s = (int(good_msgs[0]["sent_timestamp_ms"]) / 1000.0) - good["startDate"].timestamp()

    # Beat 2 — break exactly one thing: revoke sns:Publish and confirm (structurally, via an
    # independent IAM read) that the revocation has actually landed before testing it.
    _revoke()

    # Beat 3 — the Task fails with AccessDenied; the state machine's own Catch routes it to
    # Denied (so the execution as a whole still ends SUCCEEDED); the history carries the
    # TaskFailed event naming the denial; the queue receives nothing for this execution.
    bad, history, denied_message, earlier_messages = _run_until_publish_denied(
        ctx, sfn, sm_arn, queue["url"], ctx.unique_name("should-not-deliver-")
    )
    assert bad["status"] == "SUCCEEDED", (
        f"Expected the Catch to route to SUCCEEDED, got: {bad['status']!r}"
    )
    types = [e["type"] for e in history]
    assert "TaskFailed" in types, f"Expected a TaskFailed event in history, got types: {types!r}"
    failed_event = next(e for e in history if e["type"] == "TaskFailed")
    failed_details = failed_event["taskFailedEventDetails"]
    cause = failed_details.get("cause") or ""
    error = failed_details.get("error") or ""
    assert error == "SNS.AuthorizationErrorException", (
        f"Expected the TaskFailed error 'SNS.AuthorizationErrorException', got: {error!r}"
    )
    masked_cause = re.sub(r"Request ID: [^;)]+", "Request ID: <request-id>", cause)
    masked_cause = re.sub(
        rf"assumed-role/{re.escape(role_name)}/[A-Za-z0-9]+ is not",
        f"assumed-role/{role_name}/<session> is not", masked_cause)
    expected_cause = (
        f"User: arn:aws:sts::{ctx.account}:assumed-role/{role_name}/<session> is not authorized "
        f"to perform: SNS:Publish on resource: {topic['arn']} because no identity-based policy "
        f"allows the SNS:Publish action (Service: AmazonSNS; Status Code: 403; Error Code: "
        f"AuthorizationError; Request ID: <request-id>; Proxy: null)"
    )
    assert masked_cause == expected_cause, (
        f"TaskFailed cause must be SNS's exact AuthorizationError for this role and topic; "
        f"expected {expected_cause!r}, got {cause!r}"
    )

    output = json.loads(bad["output"])
    assert output.get("handled") == "denied", (
        f"Expected the Catch's Denied state to produce handled='denied', got: {output!r}"
    )
    error_info = output.get("errorInfo") or {}
    assert error_info.get("Error") == error, (
        f"Execution output errorInfo.Error {error_info.get('Error')!r} does not match the "
        f"TaskFailed event's error {error!r}"
    )
    assert error_info.get("Cause") == cause, (
        f"Execution output errorInfo.Cause {error_info.get('Cause')!r} does not match the "
        f"TaskFailed event's cause {cause!r}"
    )

    # Absence, held for three times the measured delivery latency (never under the floor): only
    # a late delivery from an earlier, not-yet-revoked attempt may arrive, never the denied one.
    hold_s = max(_MIN_ABSENCE_S, 3 * latency_s)
    sqs = ctx.client("sqs")
    hold_until = time.monotonic() + hold_s
    while True:
        remaining = hold_until - time.monotonic()
        if remaining <= 0:
            break
        resp = sqs.receive_message(
            QueueUrl=queue["url"], MaxNumberOfMessages=10,
            WaitTimeSeconds=max(1, min(5, int(remaining))))
        for msg in resp.get("Messages", []):
            delivered = json.loads(msg["Body"]).get("Message")
            assert delivered in earlier_messages, (
                f"the denied execution's message {denied_message!r} (or an unknown one) reached the "
                f"queue within {hold_s:.0f}s: {delivered!r}"
            )
            sqs.delete_message(QueueUrl=queue["url"], ReceiptHandle=msg["ReceiptHandle"])

    # Beat 4 — restore, then the identical call succeeds and delivers again.
    _grant()
    restored, restored_types = _run_until_publish_authorized(
        sfn, sm_arn, json.dumps({"message": "control-restored"})
    )
    assert restored["status"] == "SUCCEEDED", (
        f"Restored call expected SUCCEEDED, got: {restored['status']!r}"
    )
    assert "TaskFailed" not in restored_types, (
        f"Restored call's Task failed and was caught; history types: {restored_types!r}"
    )
    restored_msgs = _wait_for_messages(ctx, queue["url"], expected_count=1, timeout_s=30)
    restored_envelope = restored_msgs[0]["body"]
    assert restored_envelope["Message"] == "control-restored", (
        f"Expected delivered envelope Message 'control-restored', got: {restored_envelope.get('Message')!r}"
    )


_XSVC_PREFIX = "sim2real-xsvc-"

_MANAGED_TAG_KEY = "sim2real:managed"

_MIN_ABSENCE_S = 15.0


def _xsvc_resource_tags() -> dict[str, str]:
    return {_MANAGED_TAG_KEY: "true", "sim2real:prefix": _XSVC_PREFIX.rstrip("-")}


def _xsvc_tags_kv() -> list[dict[str, str]]:
    return [{"Key": k, "Value": v} for k, v in _xsvc_resource_tags().items()]


def _xsvc_tags_lower() -> list[dict[str, str]]:
    return [{"key": k, "value": v} for k, v in _xsvc_resource_tags().items()]


def _xname(ctx: Any, kind: str) -> str:
    """A unique, prefix-tagged resource name: sim2real-xsvc-<kind>-<uuid>."""
    return ctx.unique_name(f"{_XSVC_PREFIX}{kind}-")


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=1.0, description="condition"):
    """Poll probe() until predicate(result) is truthy; return the final result (raises on timeout)."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _delete_role(ctx, role_name: str) -> None:
    """IAM roles need every attached + inline policy removed before deletion."""
    iam = ctx.client("iam")
    for p in iam.list_attached_role_policies(RoleName=role_name).get("AttachedPolicies", []):
        iam.detach_role_policy(RoleName=role_name, PolicyArn=p["PolicyArn"])
    for pname in iam.list_role_policies(RoleName=role_name).get("PolicyNames", []):
        iam.delete_role_policy(RoleName=role_name, PolicyName=pname)
    iam.delete_role(RoleName=role_name)


def _create_queue(ctx) -> dict[str, str]:
    """Create an SQS queue (registers delete_queue teardown). Returns {name,url,arn}."""
    name = _xname(ctx, "q")
    sqs = ctx.client("sqs")
    resp = sqs.create_queue(QueueName=name, tags=_xsvc_resource_tags())
    url = resp["QueueUrl"]
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    return {"name": name, "url": url, "arn": arn}


def _create_topic(ctx) -> dict[str, str]:
    """Create an SNS topic (registers delete_topic teardown). Returns {name,arn}."""
    name = _xname(ctx, "topic")
    sns = ctx.client("sns")
    arn = sns.create_topic(Name=name, Tags=_xsvc_tags_kv())["TopicArn"]
    ctx.on_cleanup(lambda: sns.delete_topic(TopicArn=arn))
    return {"name": name, "arn": arn}


def _subscribe_queue_to_topic(ctx, topic: dict[str, str], queue: dict[str, str]) -> None:
    """Grant the topic send-access to the queue, subscribe it, and wait for the subscription
    to leave PendingConfirmation (sqs-protocol subscriptions auto-confirm, but not instantly)."""
    sqs = ctx.client("sqs")
    sns = ctx.client("sns")
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "sns.amazonaws.com"},
                "Action": "sqs:SendMessage",
                "Resource": queue["arn"],
                "Condition": {"ArnEquals": {"aws:SourceArn": topic["arn"]}},
            }
        ],
    }
    sqs.set_queue_attributes(QueueUrl=queue["url"], Attributes={"Policy": json.dumps(policy)})
    sub_arn = sns.subscribe(TopicArn=topic["arn"], Protocol="sqs", Endpoint=queue["arn"])["SubscriptionArn"]
    ctx.on_cleanup(lambda: _tolerant_unsubscribe(sns, sub_arn))
    _poll_until(
        lambda: sns.get_subscription_attributes(SubscriptionArn=sub_arn),
        lambda r: r["Attributes"].get("PendingConfirmation") == "false",
        timeout_s=30,
        interval_s=2,
        description="SNS->SQS subscription confirmed",
    )


def _tolerant_unsubscribe(sns, sub_arn: str) -> None:
    try:
        sns.unsubscribe(SubscriptionArn=sub_arn)
    except ClientError as e:
        if e.response["Error"]["Code"] != "NotFound":
            raise


def _wait_for_messages(ctx, queue_url, expected_count=1, timeout_s=60.0, delete=True):
    """Poll SQS until expected_count messages arrive; return them (raises on timeout)."""
    sqs = ctx.client("sqs")
    messages: list[dict[str, Any]] = []
    deadline = time.monotonic() + timeout_s
    while len(messages) < expected_count and time.monotonic() < deadline:
        remaining = max(1, int(deadline - time.monotonic()))
        resp = sqs.receive_message(
            QueueUrl=queue_url,
            MaxNumberOfMessages=min(10, expected_count - len(messages)),
            WaitTimeSeconds=min(5, remaining),
            MessageAttributeNames=["All"],
            AttributeNames=["SentTimestamp"],
        )
        for msg in resp.get("Messages", []):
            try:
                body = json.loads(msg["Body"])
            except (json.JSONDecodeError, ValueError):
                body = msg["Body"]
            messages.append(
                {
                    "body": body,
                    "message_id": msg["MessageId"],
                    "receipt_handle": msg["ReceiptHandle"],
                    "attributes": msg.get("MessageAttributes", {}),
                    "sent_timestamp_ms": msg.get("Attributes", {}).get("SentTimestamp"),
                }
            )
            if delete:
                sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
    if len(messages) < expected_count:
        raise AssertionError(
            f"Expected {expected_count} messages, got {len(messages)} within {timeout_s}s"
        )
    return messages


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
