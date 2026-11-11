"""stack-update-stack-policy-during-update-url-overrides-once."""

from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "stack-update-stack-policy-during-update-url-overrides-once"
GROUP = "stack-policy"
SERVICES = ["cloudformation", "s3"]

#: Deny removing any resource, allow every other update.
_DENY_DELETE = {"Statement": [
    {"Effect": "Deny", "Action": "Update:Delete", "Principal": "*", "Resource": "*"},
    {"Effect": "Allow", "Action": "Update:*", "Principal": "*", "Resource": "*"},
]}
_ALLOW_ALL = {"Statement": [{"Effect": "Allow", "Action": "Update:*", "Principal": "*", "Resource": "*"}]}


@tags("axis:happy-path", "cap:c7", "concern:deploy", "plane:control")
def run(ctx) -> None:
    """An S3 StackPolicyDuringUpdateURL lets one update remove a resource the stored policy
    protects; the stored policy is unchanged and the next removal without it is denied at the stack
    level before any resource delete starts, naming the policy statement's own resource pattern.

    Reference: https://docs.aws.amazon.com/AWSCloudFormation/latest/APIReference/API_UpdateStack.html"""
    cfn, s3 = ctx.client("cloudformation"), ctx.client("s3")
    bucket = _bucket(ctx, s3)
    s3.put_object(Bucket=bucket, Key="allow.json", Body=json.dumps(_ALLOW_ALL).encode())
    name = ctx.unique_name("sim2real-cfn-durl-")
    stack_id = _create(ctx, cfn, name, _template("A", "B", "C"), StackPolicyBody=json.dumps(_DENY_DELETE))
    assert _settle(cfn, stack_id, timeout_s=_cap(ctx, _DEADLINE_S)) == "CREATE_COMPLETE", f"create ended {_stack(cfn, stack_id)!r}"

    cfn.update_stack(StackName=stack_id, TemplateBody=_template("A", "C"),
                     StackPolicyDuringUpdateURL=_url(s3, bucket, "allow.json"))
    assert _settle(cfn, stack_id, timeout_s=_cap(ctx, _DEADLINE_S)) == "UPDATE_COMPLETE", f"overridden removal ended {_stack(cfn, stack_id)!r}"
    assert _resources(cfn, stack_id) == ["A", "C"], f"after the overridden removal: {_resources(cfn, stack_id)!r}"
    stored = json.loads(cfn.get_stack_policy(StackName=stack_id)["StackPolicyBody"])
    assert stored == _DENY_DELETE, f"the override must not replace the stored policy: {stored!r}"

    before = len(_events(cfn, stack_id))
    cfn.update_stack(StackName=stack_id, TemplateBody=_template("A"))
    assert _settle(cfn, stack_id, timeout_s=_cap(ctx, _DEADLINE_S)) == "UPDATE_ROLLBACK_COMPLETE", f"plain removal ended {_stack(cfn, stack_id)!r}"
    rows = _rows(_events(cfn, stack_id)[before:])
    denied = [(status, reason) for rid, status, reason in rows
              if rid == name and status == "UPDATE_ROLLBACK_IN_PROGRESS"]
    assert denied == [("UPDATE_ROLLBACK_IN_PROGRESS", "Action denied by stack policy: Statement [#1] does not "
                                                       "allow [Update:Delete] for resource [*];")], (
        f"the stack-level denial event: {denied!r}")
    c_deletes = [status for rid, status, _ in rows if rid == "C" and status.startswith("DELETE_")]
    assert c_deletes == [], f"the denied removal must start no delete of C, events show {c_deletes!r}"
    assert _resources(cfn, stack_id) == ["A", "C"], f"C must remain: {_resources(cfn, stack_id)!r}"


def _template(*handles: str) -> str:
    return json.dumps({"AWSTemplateFormatVersion": "2010-09-09",
                       "Resources": {h: {"Type": "AWS::CloudFormation::WaitConditionHandle"} for h in handles}})


def _resources(cfn, stack_id: str) -> list[str]:
    return sorted(r["LogicalResourceId"] for r in cfn.describe_stack_resources(StackName=stack_id)["StackResources"])


# ===== helpers =====

_TAGS = [{"Key": "sim2real", "Value": CHECK}]

#: A stack transition here takes seconds to a few minutes; the bound only stops a hung poll.
_DEADLINE_S = 600.0


def _cap(ctx, own_s, margin_s=15.0):
    """Bound a wait by the check's remaining budget."""
    left = ctx.time_left()
    return own_s if left is None else max(1.0, min(own_s, left - margin_s))


def _poll(probe, done, *, timeout_s: float = _DEADLINE_S, interval_s: float = 3.0, what: str = "condition"):
    """Call ``probe()`` until ``done(result)`` holds and return the result; raise at the deadline."""
    deadline = time.monotonic() + timeout_s
    while True:
        last = probe()
        if done(last):
            return last
        if time.monotonic() >= deadline:
            raise AssertionError(f"{what} not reached within {timeout_s}s; last {last!r}")
        time.sleep(interval_s)


def _stack(cfn, stack_id: str) -> dict:
    return cfn.describe_stacks(StackName=stack_id)["Stacks"][0]


def _settle(cfn, stack_id: str, timeout_s: float = _DEADLINE_S) -> str:
    """The stack's status once no operation is in progress on it."""
    return _poll(lambda: _stack(cfn, stack_id)["StackStatus"], lambda s: not s.endswith("_IN_PROGRESS"),
                 timeout_s=timeout_s, what=f"stack {stack_id} settled")


def _delete_stack(cfn, stack_id: str) -> None:
    """Delete the stack and wait for DELETE_COMPLETE by id; DELETE_FAILED or a timeout raises."""
    status = _stack(cfn, stack_id)["StackStatus"]
    if status == "UPDATE_IN_PROGRESS":
        cfn.cancel_update_stack(StackName=stack_id)
    if status != "CREATE_IN_PROGRESS":
        status = _settle(cfn, stack_id)
    if status == "DELETE_COMPLETE":
        return
    cfn.delete_stack(StackName=stack_id)
    final = _poll(lambda: _stack(cfn, stack_id)["StackStatus"],
                  lambda s: s in ("DELETE_COMPLETE", "DELETE_FAILED"), what=f"stack {stack_id} deleted")
    if final != "DELETE_COMPLETE":
        raise RuntimeError(f"stack {stack_id} ended {final}: {_stack(cfn, stack_id).get('StackStatusReason')!r}")


def _create(ctx, cfn, name: str, body: str, **kw) -> str:
    """CreateStack with its delete registered at once; returns the StackId."""
    stack_id = cfn.create_stack(StackName=name, TemplateBody=body, Tags=_TAGS, **kw)["StackId"]
    ctx.on_cleanup(lambda: _delete_stack(cfn, stack_id))
    return stack_id


def _events(cfn, stack_id: str) -> list[dict]:
    """Every stack event, oldest first (the API pages newest first)."""
    out: list[dict] = []
    for page in cfn.get_paginator("describe_stack_events").paginate(StackName=stack_id):
        out.extend(page["StackEvents"])
    return out[::-1]


def _rows(events: list[dict], *keys: str) -> list[tuple]:
    """``(LogicalResourceId, ResourceStatus, ResourceStatusReason, *keys)`` per event; absent is None."""
    return [(e["LogicalResourceId"], e["ResourceStatus"], e.get("ResourceStatusReason"),
             *(e.get(k) for k in keys)) for e in events]


def _bucket(ctx, s3) -> str:
    """A fresh bucket in the stack's region, emptied and deleted at cleanup."""
    name = ctx.unique_name("sim2real-cfn-")
    kwargs: dict = {"Bucket": name}
    # us-east-1 is the one region that refuses an explicit LocationConstraint.
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, name))
    s3.put_bucket_tagging(Bucket=name, Tagging={"TagSet": _TAGS})
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


def _url(s3, bucket: str, key: str) -> str:
    """The object's regional path-style S3 URL; CloudFormation reads it with the caller's credentials."""
    return f"https://s3.{s3.meta.region_name}.amazonaws.com/{bucket}/{key}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
