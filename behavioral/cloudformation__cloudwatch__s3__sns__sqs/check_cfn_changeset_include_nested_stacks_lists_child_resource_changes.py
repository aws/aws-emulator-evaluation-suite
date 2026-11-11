"""cfn-changeset-include-nested-stacks-lists-child-resource-changes."""

from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-changeset-include-nested-stacks-lists-child-resource-changes"

GROUP = "change_sets"

SERVICES = ["cloudformation", "cloudwatch", "s3", "sns", "sqs"]

_PARENT = json.dumps({
    "Parameters": {"ChildTemplateUrl": {"Type": "String"}, "ChildQueueName": {"Type": "String"}},
    "Resources": {
        "Child": {"Type": "AWS::CloudFormation::Stack",
                  "Properties": {"TemplateURL": {"Ref": "ChildTemplateUrl"},
                                 "Parameters": {"QueueName": {"Ref": "ChildQueueName"}}}},
    },
})


def _child(visibility_timeout: int) -> str:
    return json.dumps({
        "Parameters": {"QueueName": {"Type": "String"}},
        "Resources": {
            "ChildQueue": {"Type": "AWS::SQS::Queue",
                           "Properties": {"QueueName": {"Ref": "QueueName"},
                                          "VisibilityTimeout": visibility_timeout}},
        },
        "Outputs": {"QueueUrl": {"Value": {"Ref": "ChildQueue"}}},
    })


@tags("axis:happy-path", "cap:c3", "concern:deploy", "concern:e2e", "plane:control")
def run(ctx) -> None:
    """IncludeNestedStacks=True makes a parent change set preview the child's resource changes, and
    executing it sets the child queue's previewed VisibilityTimeout without replacing the queue.
    """
    cfn = ctx.client("cloudformation")
    s3 = ctx.client("s3")
    sqs = ctx.client("sqs")

    bucket = _xname(ctx, "nest-b")
    s3.create_bucket(Bucket=bucket,
                     CreateBucketConfiguration={"LocationConstraint": ctx.region})
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": _tags_kv()})
    # Registered before the first upload, so an aborted run still empties and removes the bucket.
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, bucket))

    queue_name = _xname(ctx, "nest-q")
    ctx.on_cleanup(lambda: _delete_queue_by_name_if_present(sqs, queue_name))

    v1_url = _put_template(ctx, s3, bucket, "child-v1.json", _child(30))
    v2_url = _put_template(ctx, s3, bucket, "child-v2.json", _child(45))

    parent, status = _create_stack_and_wait(
        ctx, _PARENT, stack_name=_xname(ctx, "nest-p"),
        parameters={"ChildTemplateUrl": v1_url, "ChildQueueName": queue_name},
        capabilities=["CAPABILITY_IAM", "CAPABILITY_NAMED_IAM", "CAPABILITY_AUTO_EXPAND"],
        timeout_s=900.0)
    assert status == "CREATE_COMPLETE", f"the parent stack ended in {status!r}"

    child_id = _physical_id(cfn, parent, "Child")
    queue_before = _physical_id(cfn, child_id, "ChildQueue")
    assert _visibility_timeout(sqs, queue_before) == "30", (
        f"setup did not take: the child queue reports "
        f"{_visibility_timeout(sqs, queue_before)!r}, expected '30'"
    )

    # ---- the change set that must see INSIDE the child ----
    cs_name = _xname(ctx, "nest-cs")
    cs_id = cfn.create_change_set(
        StackName=parent, ChangeSetName=cs_name, ChangeSetType="UPDATE",
        UsePreviousTemplate=True, IncludeNestedStacks=True,
        Parameters=[{"ParameterKey": "ChildTemplateUrl", "ParameterValue": v2_url},
                    {"ParameterKey": "ChildQueueName", "ParameterValue": queue_name}],
        Capabilities=["CAPABILITY_IAM", "CAPABILITY_NAMED_IAM", "CAPABILITY_AUTO_EXPAND"],
    )["Id"]
    ctx.on_cleanup(lambda: _delete_change_set_if_present(cfn, cs_id))
    cs_status = _poll_until(lambda: _change_set(cfn, cs_id)["Status"],
                            lambda s: s in {"CREATE_COMPLETE", "FAILED"},
                            timeout_s=600.0, interval_s=3.0,
                            description=f"parent change set {cs_name}")
    parent_cs = _change_set(cfn, cs_id)
    assert cs_status == "CREATE_COMPLETE", (
        f"the parent change set ended {cs_status!r}: {parent_cs.get('StatusReason')!r}"
    )

    nested_ids = [c["ResourceChange"]["ChangeSetId"] for c in parent_cs["Changes"]
                  if c["ResourceChange"]["ResourceType"] == "AWS::CloudFormation::Stack"
                  and c["ResourceChange"].get("ChangeSetId")]
    assert len(nested_ids) == 1, (
        f"IncludeNestedStacks=True must surface exactly one nested ChangeSetId; the parent's "
        f"changes were {parent_cs['Changes']!r}"
    )
    nested = _change_set(cfn, nested_ids[0])
    assert nested["Status"] == "CREATE_COMPLETE", f"the nested change set is {nested!r}"
    assert [c["ResourceChange"]["LogicalResourceId"] for c in nested["Changes"]] == ["ChildQueue"], (
        f"the nested change set must name the child's own modified resource, got "
        f"{nested['Changes']!r}"
    )
    assert nested["Changes"][0]["ResourceChange"]["Action"] == "Modify", (
        f"a VisibilityTimeout change is a Modify, not a replacement: "
        f"{nested['Changes'][0]!r}"
    )

    # ---- execute the parent; the previewed child change must be exactly what happened ----
    cfn.execute_change_set(ChangeSetName=cs_id)
    executed = _poll_until(lambda: _stack_status(cfn, parent), lambda s: s in _UPDATE_TERMINAL,
                           timeout_s=900.0, interval_s=5.0,
                           description=f"execution of {cs_name}")
    assert executed == "UPDATE_COMPLETE", f"the parent update ended in {executed!r}"

    queue_after = _physical_id(cfn, child_id, "ChildQueue")
    assert _visibility_timeout(sqs, queue_after) == "45", (
        f"the child resource did not pick up the previewed change: "
        f"{_visibility_timeout(sqs, queue_after)!r}"
    )
    assert queue_after == queue_before, (
        f"a Modify must not replace the child resource: {queue_before!r} -> {queue_after!r}"
    )


_XSVC_PREFIX = "sim2real-xsvc-"

_NO_SUCH_QUEUE = "AWS.SimpleQueueService.NonExistentQueue"

_CREATE_TERMINAL = {"CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED",
                    "DELETE_COMPLETE", "DELETE_FAILED", "GONE"}

_UPDATE_TERMINAL = {"UPDATE_COMPLETE", "UPDATE_FAILED", "UPDATE_ROLLBACK_COMPLETE",
                    "UPDATE_ROLLBACK_FAILED", "GONE"}


def _xname(ctx: Any, kind: str) -> str:
    """A unique, prefix-tagged resource name: sim2real-xsvc-<kind>-<uuid>."""
    return ctx.unique_name(f"{_XSVC_PREFIX}{kind}-")


def _tags_kv() -> list[dict[str, str]]:
    return [{"Key": "sim2real:managed", "Value": "true"},
            {"Key": "sim2real:prefix", "Value": _XSVC_PREFIX.rstrip("-")}]


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


def _put_template(ctx, s3, bucket: str, key: str, body: str) -> str:
    """Upload a nested-stack template and return its S3 URL in the stack's region."""
    s3.put_object(Bucket=bucket, Key=key, Body=body.encode(),
                  ContentType="application/json")
    return ctx.s3_object_url(f"https://s3.{ctx.region}.amazonaws.com/{bucket}/{key}", bucket, key)


def _empty_and_delete_bucket(s3, bucket: str) -> None:
    """Delete every object version, then the bucket. Teardown, so failures PRINT."""
    try:
        for page in s3.get_paginator("list_object_versions").paginate(Bucket=bucket):
            victims = [{"Key": o["Key"], "VersionId": o["VersionId"]}
                       for o in page.get("Versions", []) + page.get("DeleteMarkers", [])]
            if victims:
                s3.delete_objects(Bucket=bucket, Delete={"Objects": victims})
        s3.delete_bucket(Bucket=bucket)
    except Exception as exc:  # noqa: BLE001 - only a not-found is tolerated
        teardown_code = (getattr(exc, "response", None) or {}).get("Error", {}).get("Code", "")
        if teardown_code not in ("NoSuchBucket",):
            raise RuntimeError(
                f"bucket {bucket} teardown failed: {type(exc).__name__}: {exc}"
            ) from exc


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


def _visibility_timeout(sqs, url: str) -> str:
    return sqs.get_queue_attributes(
        QueueUrl=url, AttributeNames=["VisibilityTimeout"])["Attributes"]["VisibilityTimeout"]


def _stack_status(cfn, name: str) -> str:
    try:
        return cfn.describe_stacks(StackName=name)["Stacks"][0]["StackStatus"]
    except ClientError:
        return "GONE"


def _physical_id(cfn, stack: str, logical_id: str) -> str:
    """The PhysicalResourceId CloudFormation currently records for a logical id."""
    return cfn.describe_stack_resource(
        StackName=stack, LogicalResourceId=logical_id)["StackResourceDetail"]["PhysicalResourceId"]


def _change_set(cfn, change_set_id: str) -> dict[str, Any]:
    """DescribeChangeSet with its Changes paginated in."""
    out: dict[str, Any] = {}
    changes: list[dict[str, Any]] = []
    token = None
    while True:
        kwargs: dict[str, Any] = {"ChangeSetName": change_set_id}
        if token:
            kwargs["NextToken"] = token
        page = cfn.describe_change_set(**kwargs)
        out = page
        changes.extend(page.get("Changes", []))
        token = page.get("NextToken")
        if not token:
            break
    out["Changes"] = changes
    return out


def _delete_change_set_if_present(cfn, change_set_id: str) -> None:
    """An executed change set cannot be deleted (InvalidChangeSetStatus); the stack teardown
    removes it."""
    try:
        cfn.delete_change_set(ChangeSetName=change_set_id)
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code")
        if code not in {"ChangeSetNotFound", "ValidationError", "InvalidChangeSetStatus"}:
            raise


def _delete_stack_and_wait(ctx, name: str, *, timeout_s=900.0) -> None:
    """Delete a stack and wait for it to go; teardown, so a failure PRINTS rather than raises."""
    cfn = ctx.client("cloudformation")
    try:
        cfn.delete_stack(StackName=name)
        final = _poll_until(lambda: _stack_status(cfn, name),
                            lambda s: s in {"DELETE_COMPLETE", "GONE", "DELETE_FAILED"},
                            timeout_s=timeout_s, interval_s=5.0,
                            description=f"delete stack {name}")
        if final == "DELETE_FAILED":
            raise RuntimeError(
                f"stack {name} ended DELETE_FAILED — its resources are stranded"
            )
    except Exception as exc:  # noqa: BLE001 - only a not-found is tolerated
        teardown_code = (getattr(exc, "response", None) or {}).get("Error", {}).get("Code", "")
        if (
            not any(t in teardown_code for t in ("NotFound", "NoSuch", "NonExistent", "DoesNotExist"))
        ):
            raise RuntimeError(
                f"stack {name} teardown failed: {type(exc).__name__}: {exc}"
            ) from exc


def _create_stack_and_wait(ctx, template: str, *, stack_name=None, parameters=None,
                           capabilities=None, timeout_s=900.0) -> tuple[str, str]:
    """create_stack, then poll to a terminal status which is RETURNED rather than asserted."""
    cfn = ctx.client("cloudformation")
    ctx.verify_account_safety()
    name = stack_name or _xname(ctx, "stk")
    kwargs: dict[str, Any] = {
        "StackName": name, "TemplateBody": template, "Tags": _tags_kv(),
        "Capabilities": capabilities or ["CAPABILITY_IAM", "CAPABILITY_NAMED_IAM"],
    }
    if parameters:
        kwargs["Parameters"] = [{"ParameterKey": k, "ParameterValue": v}
                                for k, v in parameters.items()]
    cfn.create_stack(**kwargs)
    ctx.on_cleanup(lambda: _delete_stack_and_wait(ctx, name, timeout_s=timeout_s))
    status = _poll_until(lambda: _stack_status(cfn, name), lambda s: s in _CREATE_TERMINAL,
                         timeout_s=timeout_s, interval_s=5.0,
                         description=f"create stack {name}")
    return name, status


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
