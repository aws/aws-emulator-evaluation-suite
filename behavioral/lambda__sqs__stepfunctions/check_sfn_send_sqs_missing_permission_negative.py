"""sfn-send-sqs-missing-permission-negative."""

from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "sfn-send-sqs-missing-permission-negative"

GROUP = "overly-permissive"

SERVICES = ["lambda", "stepfunctions", "sqs"]

_TRUST_RACE_MARKERS = (
    "not authorized to assume",
    "cannot be assumed",
    "is not authorized to perform: sts:AssumeRole",
)

_ACCESS_DENIED_MARKERS = ("accessdenied", "taskfailed", "states.taskfailed")


def _run_sfn_to_terminal(sfn, sm_arn: str, input_str: str, max_attempts: int = 8):
    """Start an execution, retrying only while it fails on the IAM-trust race.

    Returns the terminal describe_execution dict. Raises AssertionError only if the
    trust never propagates within the budget (a genuine, reportable condition).
    """
    desc = None
    for attempt in range(max_attempts):
        execution = sfn.start_execution(stateMachineArn=sm_arn, input=input_str)
        exec_arn = execution["executionArn"]
        desc = _poll_until(
            lambda: sfn.describe_execution(executionArn=exec_arn),
            lambda d: d["status"] in ("SUCCEEDED", "FAILED", "TIMED_OUT", "ABORTED"),
            timeout_s=60,
            interval_s=3,
        )
        if desc["status"] != "FAILED":
            return desc
        cause = (desc.get("cause") or "") + (desc.get("error") or "")
        if not any(m in cause for m in _TRUST_RACE_MARKERS):
            return desc
        time.sleep(10 + attempt * 5)
    raise AssertionError(
        f"Step Functions role trust did not propagate after {max_attempts} attempts "
        f"(last cause: {desc.get('cause') if desc else 'n/a'})"
    )


def _run_sfn_until_authorized(sfn, sm_arn: str, input_str: str, max_attempts: int = 8):
    """Start an execution, retrying while it fails on IAM propagation lag (trust OR permission).

    Real AWS showed both directions lag GetRolePolicy: a role can read back a policy as attached
    before the SendMessage grant is authorization-effective, and the same gap exists for the
    initial trust race. Used only on calls expected to succeed — a persistent failure for any
    other reason is returned immediately, not masked.
    """
    race_markers = _TRUST_RACE_MARKERS + _ACCESS_DENIED_MARKERS
    desc = None
    for attempt in range(max_attempts):
        execution = sfn.start_execution(stateMachineArn=sm_arn, input=input_str)
        exec_arn = execution["executionArn"]
        desc = _poll_until(
            lambda: sfn.describe_execution(executionArn=exec_arn),
            lambda d: d["status"] in ("SUCCEEDED", "FAILED", "TIMED_OUT", "ABORTED"),
            timeout_s=60,
            interval_s=3,
        )
        if desc["status"] != "FAILED":
            return desc
        cause = ((desc.get("cause") or "") + (desc.get("error") or "")).lower()
        if not any(m in cause for m in race_markers):
            return desc
        time.sleep(10 + attempt * 5)
    raise AssertionError(
        f"Authorization did not propagate after {max_attempts} attempts "
        f"(last cause: {desc.get('cause') if desc else 'n/a'})"
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


def _run_sfn_until_permission_revoked(
    ctx, sfn, sm_arn: str, queue_url: str, input_str: str, max_attempts: int = 6
):
    """Run until the revoked permission actually bites (IAM authz propagation lags GetRolePolicy).

    A SUCCEEDED result here means the delete_role_policy call has not yet propagated to the
    authorization layer, not that the target is over-permissive — so it is retried with backoff,
    draining any message that slipped through, rather than trusted on the first try.
    """
    desc = None
    for attempt in range(max_attempts):
        desc = _run_sfn_to_terminal(sfn, sm_arn, input_str)
        if desc["status"] != "SUCCEEDED":
            return desc
        _drain_queue(ctx, queue_url)
        time.sleep(5 + attempt * 5)
    raise AssertionError(
        f"sqs:SendMessage still succeeded after {max_attempts} attempts following "
        "delete_role_policy; IAM authorization did not revoke within budget"
    )


@tags("axis:negative-delivery", "cap:c3", "cap:c4", "concern:data-plane", "concern:e2e", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """SFN role lacks sqs:SendMessage; SQS task state must fail, queue must remain empty; the
    identical call succeeds once granted, and again once regranted after revocation."""
    queue = _create_queue(ctx)

    sfn = ctx.client("stepfunctions")
    iam = ctx.client("iam")

    role_name = ctx.unique_name("sfn-nosqs-role-")
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
    role = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=trust)
    role_arn = role["Role"]["Arn"]
    ctx.on_cleanup(lambda: _delete_role(ctx, role_name))

    policy_name = "sqs-send"
    policy_doc = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": "sqs:SendMessage",
                    "Resource": queue["arn"],
                }
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
            description="sqs-send policy readable",
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
            lambda: _absent(),
            lambda gone: gone,
            timeout_s=30,
            interval_s=2,
            description="sqs-send policy removed",
        )

    _grant()

    sm_name = ctx.unique_name("sm-nosqs-")
    definition = json.dumps(
        {
            "StartAt": "SendToSQS",
            "States": {
                "SendToSQS": {
                    "Type": "Task",
                    "Resource": "arn:aws:states:::sqs:sendMessage",
                    "Parameters": {
                        "QueueUrl": queue["url"],
                        "MessageBody.$": "$.message",
                    },
                    "End": True,
                }
            },
        }
    )
    sm = sfn.create_state_machine(name=sm_name, definition=definition, roleArn=role_arn)
    sm_arn = sm["stateMachineArn"]
    ctx.on_cleanup(
        lambda: ctx.client("stepfunctions").delete_state_machine(stateMachineArn=sm_arn)
    )

    # Beat 1 — positive control: the role, the definition and the wiring all work before
    # anything is broken, so a later FAILED cannot be blamed on a dead delivery path.
    control_desc = _run_sfn_until_authorized(
        sfn, sm_arn, json.dumps({"message": "control-positive"})
    )
    assert control_desc["status"] == "SUCCEEDED", (
        f"Positive control expected SUCCEEDED, got: {control_desc['status']}"
    )
    control_msgs = _wait_for_messages(ctx, queue["url"], expected_count=1, timeout_s=30)
    assert _body_str(control_msgs[0]) == "control-positive", (
        f"Expected 'control-positive', got: {_body_str(control_msgs[0])}"
    )

    # Beat 2 — break exactly one thing: revoke sqs:SendMessage and confirm (structurally,
    # via an independent IAM read) that the revocation has actually landed before testing it.
    _revoke()

    # Beat 3+4 — the specific refusal, and the effect absent at the destination.
    desc = _run_sfn_until_permission_revoked(
        ctx, sfn, sm_arn, queue["url"], json.dumps({"message": "should-fail"})
    )
    assert desc["status"] == "FAILED", f"Expected FAILED, got: {desc['status']}"
    error = desc.get("error", "") or ""
    cause = desc.get("cause", "") or ""
    combined = (error + cause).lower()
    assert any(kw in combined for kw in _ACCESS_DENIED_MARKERS), (
        f"Expected access denied/task failed error, got error={error}, cause={cause}"
    )

    sqs_client = ctx.client("sqs")
    attrs = sqs_client.get_queue_attributes(
        QueueUrl=queue["url"], AttributeNames=["ApproximateNumberOfMessages"]
    )
    count = int(attrs["Attributes"]["ApproximateNumberOfMessages"])
    assert count == 0, f"Queue should be empty, got {count} messages"
    empty_receive = sqs_client.receive_message(
        QueueUrl=queue["url"], MaxNumberOfMessages=1, WaitTimeSeconds=1
    )
    assert not empty_receive.get("Messages"), (
        f"Expected no visible messages, got: {empty_receive.get('Messages')}"
    )

    # Beat 5+6 — restore, then the identical call succeeds again.
    _grant()
    restored_desc = _run_sfn_until_authorized(
        sfn, sm_arn, json.dumps({"message": "control-restored"})
    )
    assert restored_desc["status"] == "SUCCEEDED", (
        f"Restored call expected SUCCEEDED, got: {restored_desc['status']}"
    )
    restored_msgs = _wait_for_messages(ctx, queue["url"], expected_count=1, timeout_s=30)
    assert _body_str(restored_msgs[0]) == "control-restored", (
        f"Expected 'control-restored', got: {_body_str(restored_msgs[0])}"
    )


_XSVC_PREFIX = "sim2real-xsvc-"

_MANAGED_TAG_KEY = "sim2real:managed"


def _xsvc_resource_tags() -> dict[str, str]:
    return {_MANAGED_TAG_KEY: "true", "sim2real:prefix": _XSVC_PREFIX.rstrip("-")}


def _xname(ctx: Any, kind: str) -> str:
    """A unique, prefix-tagged resource name: sim2real-xsvc-<kind>-<uuid>."""
    return ctx.unique_name(f"{_XSVC_PREFIX}{kind}-")


def _poll_until(
    probe, predicate, *, timeout_s=60.0, interval_s=1.0, description="condition"
):
    """Poll probe() until predicate(result) is truthy; return the final result (raises on timeout)."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(
        f"{description} not met within {timeout_s}s. Last result: {last!r}"
    )


def _delete_role(ctx, role_name: str) -> None:
    """IAM roles need every attached + inline policy removed before deletion."""
    iam = ctx.client("iam")
    try:
        for p in iam.list_attached_role_policies(RoleName=role_name).get(
            "AttachedPolicies", []
        ):
            iam.detach_role_policy(RoleName=role_name, PolicyArn=p["PolicyArn"])
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise
    try:
        for pname in iam.list_role_policies(RoleName=role_name).get("PolicyNames", []):
            iam.delete_role_policy(RoleName=role_name, PolicyName=pname)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise
    try:
        iam.delete_role(RoleName=role_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _create_queue(ctx, fifo: bool = False, **attrs: str) -> dict[str, str]:
    """Create an SQS queue (registers delete_queue teardown). Returns {name,url,arn}."""
    base = _xname(ctx, "q")
    name = f"{base}.fifo" if fifo else base
    sqs = ctx.client("sqs")
    create_attrs = dict(attrs)
    if fifo:
        create_attrs["FifoQueue"] = "true"
    resp = sqs.create_queue(
        QueueName=name, Attributes=create_attrs, tags=_xsvc_resource_tags()
    )
    url = resp["QueueUrl"]
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])[
        "Attributes"
    ]["QueueArn"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    return {"name": name, "url": url, "arn": arn}


def _get_body(msg: dict):
    """Extract message body regardless of key casing (Body vs body). Returns str or dict."""
    raw = msg.get("Body") or msg.get("body")
    if raw is None:
        return ""
    return raw


def _body_str(msg: dict) -> str:
    """Extract message body as string (JSON-encode if already a dict)."""
    raw = _get_body(msg)
    if isinstance(raw, dict):
        return json.dumps(raw)
    return str(raw) if raw is not None else ""


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
        )
        for msg in resp.get("Messages", []):
            messages.append(msg)
            if delete:
                sqs.delete_message(
                    QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"]
                )
    if len(messages) < expected_count:
        raise AssertionError(
            f"Expected {expected_count} messages, got {len(messages)} within {timeout_s}s"
        )
    return messages


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
