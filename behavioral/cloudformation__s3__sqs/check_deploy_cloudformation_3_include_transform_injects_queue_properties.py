"""deploy-cloudformation-3-include-transform-injects-queue-properties."""

from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-cloudformation-3-include-transform-injects-queue-properties"

GROUP = "deploy-cfn-include-transform"

SERVICES = ["cloudformation", "s3", "sqs"]

_VISIBILITY_TIMEOUT = 47


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:deploy", "concern:e2e",
      "dp:api", "plane:data")
def run(ctx) -> None:
    """An AWS::Include snippet fetched from S3 is merged into a queue's Properties at deploy
    time: the processed template carries it, the original does not, and the deployed queue
    actually has the injected VisibilityTimeout and tag and carries messages.
    """
    cfn = ctx.client("cloudformation")
    s3 = ctx.client("s3")
    sqs = ctx.client("sqs")

    bucket = _xname(ctx, "incl")
    queue_name = _xname(ctx, "incl-q")
    stack_name = _xname(ctx, "incl-stk")
    key = "snippets/queue-properties.yaml"
    tag_value = f"from-include-{queue_name}"

    _make_bucket(ctx, s3, bucket)
    s3.put_object(Bucket=bucket, Key=key, Body=_snippet(_VISIBILITY_TIMEOUT, tag_value))
    # Registered before the stack so LIFO runs it after the stack delete: the by-name delete is
    # the handle that certainly reaches the queue if the stack itself cannot be deleted.
    ctx.on_cleanup(lambda: _delete_queue_by_name_if_present(sqs, queue_name))

    template = _include_template(queue_name, f"s3://{bucket}/{key}")
    stack_id, status = _create_stack_and_wait(ctx, template, stack_name=stack_name)
    assert status == "CREATE_COMPLETE", (
        f"a stack whose queue Properties come from a valid AWS::Include snippet must reach "
        f"CREATE_COMPLETE; got {status!r} with stack-level reasons {_stack_reasons(cfn, stack_id)!r}"
    )

    # ---- The two template stages differ by exactly the include ----
    original = _template_body(cfn, stack_id, "Original")
    processed = _template_body(cfn, stack_id, "Processed")
    orig_props = original["Resources"]["Q"]["Properties"]
    proc_props = processed["Resources"]["Q"]["Properties"]
    assert "Fn::Transform" in orig_props, (
        f"the Original stage must be the template as submitted, Fn::Transform included; its "
        f"queue Properties were {orig_props!r}"
    )
    assert not _has_key(original, "VisibilityTimeout"), (
        f"the Original stage must NOT contain the included VisibilityTimeout -- it only exists in "
        f"the S3 snippet; Original was {original!r}"
    )
    assert proc_props.get("VisibilityTimeout") == _VISIBILITY_TIMEOUT, (
        f"the Processed stage must carry the VisibilityTimeout merged in from the snippet "
        f"({_VISIBILITY_TIMEOUT!r}); its queue Properties were {proc_props!r}"
    )
    assert {"Key": "injected-by", "Value": tag_value} in [dict(t) for t in proc_props.get("Tags", [])], (
        f"the Processed stage must carry the tag merged in from the snippet; its queue "
        f"Properties were {proc_props!r}"
    )
    assert not _has_key(processed, "Fn::Transform"), (
        f"the Processed stage must have the transform fully expanded away; it still contains "
        f"Fn::Transform: {processed!r}"
    )

    # ---- The deployed queue really has the injected values ----
    queue_url = _output(cfn, stack_id, "QueueUrl")
    assert queue_url == sqs.get_queue_url(QueueName=queue_name)["QueueUrl"], (
        f"the stack's QueueUrl output {queue_url!r} is not the queue SQS knows as {queue_name!r}"
    )
    vt = sqs.get_queue_attributes(QueueUrl=queue_url,
                                  AttributeNames=["VisibilityTimeout"])["Attributes"]
    assert vt.get("VisibilityTimeout") == str(_VISIBILITY_TIMEOUT), (
        f"SQS reports VisibilityTimeout {vt.get('VisibilityTimeout')!r}; the included snippet set "
        f"{_VISIBILITY_TIMEOUT!r} (the SQS default is 30)"
    )
    qtags = sqs.list_queue_tags(QueueUrl=queue_url).get("Tags", {})
    assert qtags.get("injected-by") == tag_value, (
        f"the queue must carry the tag injected by the snippet; SQS reports tags {qtags!r}"
    )

    # ---- And it works as a queue ----
    body = f"include-roundtrip-{queue_name}"
    sent = sqs.send_message(QueueUrl=queue_url, MessageBody=body)
    received = _receive_one(sqs, queue_url, timeout_s=120.0)
    assert received["Body"] == body and received["MessageId"] == sent["MessageId"], (
        f"the message received {received!r} is not the one sent (id {sent['MessageId']!r}, "
        f"body {body!r})"
    )
    sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=received["ReceiptHandle"])

    # ---- Deleting the stack takes the queue with it ----
    final = _delete_stack_in_flow(cfn, stack_id)
    assert final == "DELETE_COMPLETE", f"DeleteStack ended {final!r}, expected DELETE_COMPLETE"
    gone = _wait_queue_gone(sqs, queue_name)
    assert gone == _NO_SUCH_QUEUE_ERR, (
        f"after DeleteStack the queue {queue_name!r} must be gone; GetQueueUrl reported {gone!r}"
    )
    listed = _list_queue_urls(sqs, queue_name)
    assert listed == [], f"ListQueues still shows {listed!r} under prefix {queue_name!r}"


_XSVC_PREFIX = "sim2real-xsvc-"

_NO_SUCH_QUEUE = "AWS.SimpleQueueService.NonExistentQueue"

_NO_SUCH_QUEUE_ERR = (_NO_SUCH_QUEUE, "The specified queue does not exist.")

_AUTO_EXPAND = ["CAPABILITY_AUTO_EXPAND"]

_STACK_TERMINAL = {"CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED",
                   "UPDATE_COMPLETE", "UPDATE_ROLLBACK_COMPLETE", "UPDATE_ROLLBACK_FAILED",
                   "DELETE_COMPLETE", "DELETE_FAILED", "GONE"}


def _xname(ctx: Any, kind: str) -> str:
    """A unique, prefix-tagged resource name: sim2real-xsvc-<kind>-<uuid>."""
    return ctx.unique_name(f"{_XSVC_PREFIX}{kind}-")


def _tags_kv() -> list[dict[str, str]]:
    return [{"Key": "sim2real:managed", "Value": "true"},
            {"Key": "sim2real:prefix", "Value": _XSVC_PREFIX.rstrip("-")}]


def _snippet(visibility_timeout: int, tag_value: str) -> bytes:
    """The YAML the include merges into the queue's Properties map."""
    return (f"VisibilityTimeout: {visibility_timeout}\n"
            f"Tags:\n"
            f"  - Key: injected-by\n"
            f"    Value: {tag_value}\n").encode()


def _include_template(queue_name: str, location: str) -> str:
    """A queue whose Properties are completed by Fn::Transform AWS::Include from `location`."""
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "Q": {
                "Type": "AWS::SQS::Queue",
                "Properties": {
                    "QueueName": queue_name,
                    "Fn::Transform": {
                        "Name": "AWS::Include",
                        "Parameters": {"Location": location},
                    },
                },
            },
        },
        "Outputs": {"QueueUrl": {"Value": {"Ref": "Q"}}},
    })


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


def _error_code(fn) -> tuple[str, str]:
    """The AWS error (code, message) fn() raises. RAISES if fn() unexpectedly SUCCEEDS."""
    try:
        ok = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code", ""), err.get("Message", "")
    raise AssertionError(f"expected this call to fail, but it succeeded and returned {ok!r}")


def _has_key(obj: Any, key: str) -> bool:
    """True if `key` appears as a mapping key anywhere in a parsed template."""
    if isinstance(obj, dict):
        return key in obj or any(_has_key(v, key) for v in obj.values())
    if isinstance(obj, list):
        return any(_has_key(v, key) for v in obj)
    return False


def _make_bucket(ctx, s3, name: str) -> None:
    kwargs: dict[str, Any] = {"Bucket": name}
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, name))


def _empty_and_delete_bucket(s3, name: str) -> None:
    """Teardown: empty then delete; a failure PRINTS rather than raises."""
    try:
        token = None
        while True:
            kw: dict[str, Any] = {"Bucket": name}
            if token:
                kw["ContinuationToken"] = token
            page = s3.list_objects_v2(**kw)
            for obj in page.get("Contents", []):
                s3.delete_object(Bucket=name, Key=obj["Key"])
            token = page.get("NextContinuationToken")
            if not token:
                break
        s3.delete_bucket(Bucket=name)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "NoSuchBucket":
            raise RuntimeError(f"bucket {name} teardown failed: {exc}") from exc


def _queue_url_or_none(sqs, name: str) -> str | None:
    try:
        return sqs.get_queue_url(QueueName=name)["QueueUrl"]
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == _NO_SUCH_QUEUE:
            return None
        raise


def _delete_queue_by_name_if_present(sqs, name: str) -> None:
    """Best-effort queue teardown by name; already-deleted is not an error."""
    url = _queue_url_or_none(sqs, name)
    if url:
        sqs.delete_queue(QueueUrl=url)


def _list_queue_urls(sqs, prefix: str) -> list[str]:
    """Every queue URL under a prefix only this check can occupy, paginated."""
    urls: list[str] = []
    token = None
    while True:
        kw: dict[str, Any] = {"QueueNamePrefix": prefix, "MaxResults": 1000}
        if token:
            kw["NextToken"] = token
        page = sqs.list_queues(**kw)
        urls.extend(page.get("QueueUrls", []))
        token = page.get("NextToken")
        if not token:
            return urls


def _wait_queue_gone(sqs, name: str, *, timeout_s=120.0) -> tuple[str, str]:
    """Poll GetQueueUrl until the queue is reported absent; return the (code, message) seen."""
    def probe():
        try:
            sqs.get_queue_url(QueueName=name)
            return ("PRESENT", "")
        except ClientError as exc:
            err = exc.response.get("Error", {})
            return err.get("Code", ""), err.get("Message", "")
    return _poll_until(probe, lambda c: c[0] != "PRESENT", timeout_s=timeout_s, interval_s=3.0,
                       description=f"queue {name} to disappear")


def _receive_one(sqs, url: str, *, timeout_s=120.0) -> dict[str, Any]:
    """Long-poll a queue until one message arrives; return it (raises on timeout)."""
    msgs = _poll_until(
        lambda: sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=1,
                                    WaitTimeSeconds=20).get("Messages", []),
        bool, timeout_s=timeout_s, interval_s=1.0, description=f"a message on {url}")
    return msgs[0]


def _stack_status(cfn, stack: str) -> str:
    try:
        return cfn.describe_stacks(StackName=stack)["Stacks"][0]["StackStatus"]
    except ClientError:
        return "GONE"


def _output(cfn, stack: str, key: str) -> str:
    outs = cfn.describe_stacks(StackName=stack)["Stacks"][0].get("Outputs", [])
    hits = [o["OutputValue"] for o in outs if o.get("OutputKey") == key]
    assert len(hits) == 1, f"stack {stack!r} has outputs {outs!r}; expected exactly one {key!r}"
    return hits[0]


def _template_body(cfn, stack: str, stage: str) -> dict[str, Any]:
    """GetTemplate for one stage, parsed (botocore decodes JSON bodies; YAML stays a string)."""
    resp = cfn.get_template(StackName=stack, TemplateStage=stage)
    assert set(resp.get("StagesAvailable", [])) == {"Original", "Processed"}, (
        f"a transformed stack must offer both template stages; StagesAvailable was "
        f"{resp.get('StagesAvailable')!r}"
    )
    body = resp["TemplateBody"]
    return json.loads(body) if isinstance(body, str) else json.loads(json.dumps(body))


def _stack_events(cfn, stack: str) -> list[dict[str, Any]]:
    """Every event for a stack, oldest first, paginated."""
    events: list[dict[str, Any]] = []
    token = None
    while True:
        kwargs: dict[str, Any] = {"StackName": stack}
        if token:
            kwargs["NextToken"] = token
        page = cfn.describe_stack_events(**kwargs)
        events.extend(page.get("StackEvents", []))
        token = page.get("NextToken")
        if not token:
            break
    return list(reversed(events))


def _stack_reasons(cfn, stack: str) -> list[str]:
    """Every ResourceStatusReason CloudFormation recorded on the stack itself."""
    return [e["ResourceStatusReason"] for e in _stack_events(cfn, stack)
            if e.get("ResourceType") == "AWS::CloudFormation::Stack"
            and e.get("ResourceStatusReason")]


def _delete_stack_quietly(ctx, stack: str, *, timeout_s=600.0) -> None:
    """Teardown: delete a stack and wait; a failure PRINTS rather than raises."""
    cfn = ctx.client("cloudformation")
    try:
        if _stack_status(cfn, stack) in {"DELETE_COMPLETE", "GONE"}:
            return
        cfn.delete_stack(StackName=stack)
        final = _poll_until(lambda: _stack_status(cfn, stack),
                            lambda s: s in {"DELETE_COMPLETE", "GONE", "DELETE_FAILED"},
                            timeout_s=timeout_s, interval_s=5.0,
                            description=f"delete stack {stack}")
        if final == "DELETE_FAILED":
            raise RuntimeError(
                f"stack {stack} ended DELETE_FAILED; its resources are stranded"
            )
    except Exception as exc:  # noqa: BLE001 - only a not-found is tolerated
        teardown_code = (getattr(exc, "response", None) or {}).get("Error", {}).get("Code", "")
        if (
            not any(t in teardown_code for t in ("NotFound", "NoSuch", "NonExistent", "DoesNotExist"))
        ):
            raise RuntimeError(
                f"stack {stack} teardown failed: {type(exc).__name__}: {exc}"
            ) from exc


def _delete_stack_in_flow(cfn, stack_id: str, *, timeout_s=600.0) -> str:
    """DeleteStack as part of the check itself; returns the terminal status by stack id."""
    cfn.delete_stack(StackName=stack_id)
    return _poll_until(lambda: _stack_status(cfn, stack_id),
                       lambda s: s in {"DELETE_COMPLETE", "DELETE_FAILED", "GONE"},
                       timeout_s=timeout_s, interval_s=5.0,
                       description=f"delete stack {stack_id}")


def _create_stack_and_wait(ctx, template: str, *, stack_name: str,
                           timeout_s=600.0) -> tuple[str, str]:
    """create_stack with CAPABILITY_AUTO_EXPAND, then poll to a terminal status RETURNED.

    The teardown is registered immediately after create_stack, before anything is polled.
    Polling is by stack id, so a deleted stack still reports DELETE_COMPLETE.
    """
    cfn = ctx.client("cloudformation")
    ctx.verify_account_safety()
    stack_id = cfn.create_stack(StackName=stack_name, TemplateBody=template, Tags=_tags_kv(),
                                Capabilities=_AUTO_EXPAND)["StackId"]
    ctx.on_cleanup(lambda: _delete_stack_quietly(ctx, stack_id))
    status = _poll_until(lambda: _stack_status(cfn, stack_id), lambda s: s in _STACK_TERMINAL,
                         timeout_s=timeout_s, interval_s=5.0,
                         description=f"create stack {stack_name}")
    return stack_id, status


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
