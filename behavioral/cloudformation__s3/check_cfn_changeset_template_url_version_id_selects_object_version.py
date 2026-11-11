"""cfn-changeset-template-url-version-id-selects-object-version."""

from __future__ import annotations

import json
import time
import uuid
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-changeset-template-url-version-id-selects-object-version"
GROUP = "change-sets"
SERVICES = ["cloudformation", "s3"]


@tags("axis:happy-path", "cap:c3", "concern:deploy", "plane:control")
def run(ctx) -> None:
    """On a versioned bucket a TemplateURL with ?versionId= deploys that noncurrent version, while the
    same URL without it deploys the current one.

    Reference: https://docs.aws.amazon.com/AWSCloudFormation/latest/APIReference/API_CreateChangeSet.html"""
    s3 = ctx.client("s3")
    cfn = ctx.client("cloudformation")
    bucket = _create_bucket(ctx, versioned=True)
    key = "templates/stack.json"
    v1 = s3.put_object(Bucket=bucket, Key=key, Body=_template("v1").encode())["VersionId"]
    s3.put_object(Bucket=bucket, Key=key, Body=_template("v2").encode())

    for marker, url in (("v1", f"{_s3_url(ctx, bucket, key)}?versionId={v1}"), ("v2", _s3_url(ctx, bucket, key))):
        stack = _new_stack_name(ctx)
        _execute(ctx, cfn, _create_ready_change_set(ctx, cfn, stack, url), "CREATE_COMPLETE")
        template, outputs, _ = _deployed(cfn, stack)
        assert outputs == {"Marker": marker}, f"{url!r} must deploy object version {marker}, got {outputs!r}"
        assert template == json.loads(_template(marker)), f"GetTemplate must return {marker}, got {template!r}"


_PREFIX = "sim2real-xsvc-"

_TAGS = [{"Key": "sim2real:managed", "Value": "true"}, {"Key": "sim2real:prefix", "Value": "sim2real-xsvc"}]

_CS_TERMINAL = {"CREATE_COMPLETE", "FAILED"}

_STACK_TERMINAL = {
    "CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED",
    "UPDATE_COMPLETE", "UPDATE_FAILED", "UPDATE_ROLLBACK_COMPLETE", "UPDATE_ROLLBACK_FAILED",
}


def _template(marker: str, *handles: str, pad: int = 0) -> str:
    """A template of WaitConditionHandles that outputs ``marker``; ``pad`` adds that many bytes of metadata."""
    doc: dict[str, Any] = {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {h: {"Type": "AWS::CloudFormation::WaitConditionHandle"} for h in handles or ("Handle",)},
        "Outputs": {"Marker": {"Value": marker}},
    }
    if pad:
        doc["Metadata"] = {"Pad": "p" * pad}
    return json.dumps(doc)


def _poll_until(probe, predicate, *, timeout_s=120.0, interval_s=2.0, description="condition", ctx=None):
    """``probe()`` until ``predicate`` holds; ``ctx`` caps the wait at the check's remaining budget."""
    left = ctx.time_left() if ctx is not None else None
    timeout_s = timeout_s if left is None else min(timeout_s, left)
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s; last result {last!r}")


def _error(fn) -> tuple[str, str]:
    """``(code, message)`` of the ClientError ``fn`` raises; a call that succeeds fails the check."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"expected the call to be refused, but it SUCCEEDED and returned {result!r}")


def _create_bucket(ctx, name: str | None = None, *, versioned: bool = False) -> str:
    s3 = ctx.client("s3")
    name = name or ctx.unique_name(_PREFIX + "tpl-")
    kwargs: dict[str, Any] = {"Bucket": name}
    # us-east-1 is the one region that refuses an explicit LocationConstraint.
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, name))
    s3.put_bucket_tagging(Bucket=name, Tagging={"TagSet": _TAGS})
    if versioned:
        s3.put_bucket_versioning(Bucket=name, VersioningConfiguration={"Status": "Enabled"})
    return name


def _empty_and_delete_bucket(s3, bucket: str) -> None:
    try:
        for page in s3.get_paginator("list_object_versions").paginate(Bucket=bucket):
            objs = [{"Key": v["Key"], "VersionId": v["VersionId"]}
                    for v in page.get("Versions", []) + page.get("DeleteMarkers", [])]
            if objs:
                failed = s3.delete_objects(Bucket=bucket, Delete={"Objects": objs}).get("Errors")
                if failed:
                    raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
        s3.delete_bucket(Bucket=bucket)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise


def _s3_host(ctx) -> str:
    """The regional S3 host CloudFormation resolves a TemplateURL against."""
    return f"s3.{ctx.region}.amazonaws.com"


def _s3_url(ctx, bucket: str, key: str, form: str = "path") -> str:
    """An object's S3 URL in one of the forms TemplateURL accepts, as cdk deploy builds it."""
    return {
        "path": f"https://{_s3_host(ctx)}/{bucket}/{key}",
        "virtual": f"https://{bucket}.{_s3_host(ctx)}/{key}",
        "global-path": f"https://s3.amazonaws.com/{bucket}/{key}",
        "global-virtual": f"https://{bucket}.s3.amazonaws.com/{key}",
    }[form]


def _stack_status(cfn, name: str) -> str:
    try:
        return cfn.describe_stacks(StackName=name)["Stacks"][0]["StackStatus"]
    except ClientError as exc:
        if exc.response["Error"]["Message"] == f"Stack with id {name} does not exist":
            return "GONE"
        raise


def _delete_stack(cfn, name: str) -> None:
    """Delete a stack and wait until it is gone; a stack that fails to delete raises."""
    if _stack_status(cfn, name) == "GONE":
        return
    cfn.delete_stack(StackName=name)
    final = _poll_until(lambda: _stack_status(cfn, name),
                        lambda s: s in {"GONE", "DELETE_COMPLETE", "DELETE_FAILED"},
                        timeout_s=600.0, interval_s=5.0, description=f"delete of stack {name}")
    if final == "DELETE_FAILED":
        raise RuntimeError(f"stack {name} ended DELETE_FAILED")


def _new_stack_name(ctx) -> str:
    """A fresh stack name whose stack, once anything creates it, is deleted at cleanup."""
    name = ctx.unique_name(_PREFIX + "stk-")
    cfn = ctx.client("cloudformation")
    ctx.on_cleanup(lambda: _delete_stack(cfn, name))
    return name


def _assert_no_stack(cfn, name: str) -> None:
    code, message = _error(lambda: cfn.describe_stacks(StackName=name))
    want = ("ValidationError", f"Stack with id {name} does not exist")
    assert (code, message) == want, f"no stack may exist after the refusal: expected {want!r}, got {(code, message)!r}"


def _change_set(ctx, cfn, change_set_id: str) -> dict[str, Any]:
    """DescribeChangeSet once its status is terminal, with every page of Changes."""
    _poll_until(lambda: cfn.describe_change_set(ChangeSetName=change_set_id)["Status"],
                lambda s: s in _CS_TERMINAL, timeout_s=300.0, description=f"change set {change_set_id}", ctx=ctx)
    out: dict[str, Any] = {}
    changes: list[dict[str, Any]] = []
    kwargs: dict[str, Any] = {"ChangeSetName": change_set_id}
    while True:
        page = cfn.describe_change_set(**kwargs)
        out = page
        changes.extend(page.get("Changes", []))
        if not page.get("NextToken"):
            break
        kwargs["NextToken"] = page["NextToken"]
    out["Changes"] = changes
    return out


def _changes(described: dict[str, Any]) -> list[tuple[str, str, str]]:
    """``(Action, LogicalResourceId, ResourceType)`` of each resource change, sorted."""
    return sorted((c["ResourceChange"]["Action"], c["ResourceChange"]["LogicalResourceId"],
                   c["ResourceChange"]["ResourceType"]) for c in described["Changes"])


def _create_ready_change_set(ctx, cfn, stack: str, url: str, change_set_type: str = "CREATE", **extra) -> dict[str, Any]:
    """CreateChangeSet from ``url``, polled to CREATE_COMPLETE and AVAILABLE."""
    cs_id = cfn.create_change_set(StackName=stack, ChangeSetName=_change_set_name(), TemplateURL=url,
                                  ChangeSetType=change_set_type, Tags=_TAGS, **extra)["Id"]
    described = _change_set(ctx, cfn, cs_id)
    assert (described["Status"], described["ExecutionStatus"]) == ("CREATE_COMPLETE", "AVAILABLE"), (
        f"the change set from {url!r} must be ready to execute: {described.get('Status')!r} "
        f"{described.get('ExecutionStatus')!r} {described.get('StatusReason')!r}"
    )
    return described


def _change_set_name() -> str:
    return "cs-" + uuid.uuid4().hex[:12]


def _execute(ctx, cfn, described: dict[str, Any], want: str) -> None:
    cfn.execute_change_set(ChangeSetName=described["ChangeSetId"])
    stack = described["StackName"]
    status = _poll_until(lambda: _stack_status(cfn, stack), lambda s: s in _STACK_TERMINAL,
                         timeout_s=600.0, interval_s=3.0, description=f"execution on stack {stack}", ctx=ctx)
    assert status == want, f"executing {described['ChangeSetName']} must leave {stack} {want}, got {status!r}"


def _refusal(cfn, stack: str, **source) -> tuple[str, str]:
    """``(code, message)`` refusing a CREATE change set for ``stack`` from ``source``."""
    return _error(lambda: cfn.create_change_set(StackName=stack, ChangeSetName=_change_set_name(),
                                                ChangeSetType="CREATE", **source))


def _deployed(cfn, stack: str) -> tuple[dict[str, Any], dict[str, str], list[tuple[str, str, str]]]:
    """The stack's original template, its outputs and its ``(logical id, type, status)`` resources."""
    body = cfn.get_template(StackName=stack, TemplateStage="Original")["TemplateBody"]
    template = json.loads(body) if isinstance(body, str) else json.loads(json.dumps(body))
    described = cfn.describe_stacks(StackName=stack)["Stacks"][0]
    outputs = {o["OutputKey"]: o["OutputValue"] for o in described.get("Outputs", [])}
    resources = sorted((r["LogicalResourceId"], r["ResourceType"], r["ResourceStatus"])
                       for r in cfn.describe_stack_resources(StackName=stack)["StackResources"])
    return template, outputs, resources


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
