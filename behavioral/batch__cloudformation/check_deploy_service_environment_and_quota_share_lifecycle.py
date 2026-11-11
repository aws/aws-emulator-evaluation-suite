"""deploy-service-environment-and-quota-share-lifecycle."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-service-environment-and-quota-share-lifecycle"
GROUP = "deploy"
SERVICES = ["batch", "cloudformation"]

# ---- CloudFormation helpers ----

_TERMINAL = frozenset({
    "CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED",
    "DELETE_COMPLETE", "DELETE_FAILED", "UPDATE_COMPLETE", "UPDATE_ROLLBACK_COMPLETE",
    "UPDATE_FAILED", "UPDATE_ROLLBACK_FAILED", "IMPORT_COMPLETE", "IMPORT_ROLLBACK_COMPLETE",
    "IMPORT_ROLLBACK_FAILED",
})
_DELETE_BUDGET_S = 600.0  # per stack; at most two stacks fit the suites' 1800 s cleanup budget


def paginate(client, op, key, **kw):
    """Every item under ``key`` across all pages of ``op``; presence and absence read every page.

    A ``key`` the operation's output does not declare fails instead of reading as [].
    """
    model = client.meta.service_model.operation_model(client.meta.method_to_api_mapping[op])
    assert key in model.output_shape.members, f"{op} output has no member {key!r}"
    return [x for page in client.get_paginator(op).paginate(**kw) for x in page.get(key, [])]


def wait_stack(cf, stack_id, terminal=_TERMINAL, timeout_s=300.0):
    """Poll DescribeStacks by StackId every 2 s until a status in ``terminal``; return it.

    Every error propagates: no ClientError ever stands for "done" or "gone".
    """
    deadline = time.monotonic() + timeout_s
    while True:
        status = cf.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
        if status in terminal:
            return status
        if time.monotonic() > deadline:
            raise AssertionError(f"stack {stack_id} still {status!r} after {timeout_s:.0f}s")
        time.sleep(2)


def delete_stack(cf, stack_id):
    """Delete by StackId within one deadline; raise unless DELETE_COMPLETE. Safe to call twice.

    A stack still creating or updating is first waited out; a failure names each resource's reason.
    """
    deadline = time.monotonic() + _DELETE_BUDGET_S
    status = cf.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
    if status == "DELETE_COMPLETE":
        return
    if status.endswith("_IN_PROGRESS") and status not in ("DELETE_IN_PROGRESS",
                                                          "REVIEW_IN_PROGRESS"):
        wait_stack(cf, stack_id, _TERMINAL, deadline - time.monotonic())
    cf.delete_stack(StackName=stack_id)
    status = wait_stack(cf, stack_id, {"DELETE_COMPLETE", "DELETE_FAILED"},
                        deadline - time.monotonic())
    if status != "DELETE_COMPLETE":
        events = stack_events(cf, stack_id)
        starts = [i for i, e in enumerate(events) if e.get("PhysicalResourceId") == stack_id
                  and e["ResourceStatus"] == "DELETE_IN_PROGRESS"]
        failed = [(e["LogicalResourceId"], e.get("ResourceStatusReason"))
                  for e in events[starts[-1] if starts else 0:]
                  if e["ResourceStatus"] == "DELETE_FAILED"]
        raise AssertionError(f"stack {stack_id} delete ended {status!r}: {failed!r}")


def delete_stack_named(cf, name, stack_id=None):
    """delete_stack by ``stack_id``, else by the StackId DescribeStacks(StackName=name) returns.

    A ``name`` CloudFormation never accepted ("does not exist") is nothing to delete; the
    client's own ``ClientError`` keeps the helper free of imports.
    """
    if stack_id is None:
        try:
            stack_id = cf.describe_stacks(StackName=name)["Stacks"][0]["StackId"]
        except cf.exceptions.ClientError as exc:
            err = exc.response["Error"]
            if (err.get("Code"), err.get("Message")) == (
                    "ValidationError", f"Stack with id {name} does not exist"):
                return
            raise
    delete_stack(cf, stack_id)


def create_stack(ctx, cf, name, template, **kw):
    """CreateStack tagged sim2real=<name> (propagates to every taggable resource); cleanup first.

    ``name`` comes from ctx.unique_name("sim2real-..."), so the tag value is unique per run. The
    cleanup is registered before the call: a stack AWS accepted is deleted even if the call raises.
    """
    created = {}
    ctx.on_cleanup(lambda: delete_stack_named(cf, name, created.get("StackId")))
    created["StackId"] = cf.create_stack(
        StackName=name, TemplateBody=template, Tags=[{"Key": "sim2real", "Value": name}], **kw
    )["StackId"]
    return created["StackId"]


def stack_outputs(cf, stack_id):
    """The stack's Outputs as {OutputKey: OutputValue}."""
    stack = cf.describe_stacks(StackName=stack_id)["Stacks"][0]
    return {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}


def stack_events(cf, stack_id):
    """Every DescribeStackEvents row of the stack, oldest first."""
    return paginate(cf, "describe_stack_events", "StackEvents", StackName=stack_id)[::-1]


def decisive_rows(events, *logical_ids):
    """``(logical id, status)`` of each non-IN_PROGRESS row, oldest first (subsequence asserts)."""
    return [
        (e["LogicalResourceId"], e["ResourceStatus"]) for e in events
        if not e["ResourceStatus"].endswith("_IN_PROGRESS")
        and (not logical_ids or e["LogicalResourceId"] in logical_ids)
    ]


def expect_error(fn, code, message, undo=None):
    """Assert ``fn()`` raises exactly ``(code, message)``.

    On an unexpected success ``undo(result)`` registers the cleanup before the failure is raised.
    """
    try:
        result = fn()
    except ClientError as exc:
        got = (exc.response["Error"].get("Code"), exc.response["Error"].get("Message"))
        assert got == (code, message), f"expected {(code, message)!r}, got {got!r}"
        return
    if undo is not None:
        undo(result)
    raise AssertionError(f"expected {code} but the call succeeded: {result!r}")


# ---- Check-specific: the template, then run(). ----

def _poll(probe, predicate, timeout_s=180.0):
    """``probe()`` every 3 s until ``predicate`` holds (Batch settles asynchronously)."""
    deadline = time.monotonic() + timeout_s
    while True:
        last = probe()
        if predicate(last):
            return last
        if time.monotonic() > deadline:
            raise AssertionError(f"not settled within {timeout_s:.0f}s: {last!r}")
        time.sleep(3)


def _template(names: dict[str, str]) -> str:
    return json.dumps({
        "Resources": {
            "SP": {
                "Type": "AWS::Batch::SchedulingPolicy",
                "Properties": {
                    "Name": names["sp"],
                    "QuotaSharePolicy": {"IdleResourceAssignmentStrategy": "FIFO"},
                },
            },
            "SE": {
                "Type": "AWS::Batch::ServiceEnvironment",
                "Properties": {
                    "ServiceEnvironmentName": names["se"],
                    "ServiceEnvironmentType": "SAGEMAKER_TRAINING",
                    "CapacityLimits": [{"MaxCapacity": 2, "CapacityUnit": "ml.m6i.large"}],
                },
            },
            "JQ": {
                "Type": "AWS::Batch::JobQueue",
                "Properties": {
                    "JobQueueName": names["jq"],
                    "JobQueueType": "SAGEMAKER_TRAINING",
                    "Priority": 1,
                    "SchedulingPolicyArn": {"Ref": "SP"},
                    "ServiceEnvironmentOrder": [{"Order": 1, "ServiceEnvironment": {"Ref": "SE"}}],
                },
                "DependsOn": ["SE", "SP"],
            },
            "QS": {
                "Type": "AWS::Batch::QuotaShare",
                "Properties": {
                    "QuotaShareName": names["qs"],
                    "JobQueue": {"Ref": "JQ"},
                    "CapacityLimits": [{"MaxCapacity": 1, "CapacityUnit": "ml.m6i.large"}],
                    "ResourceSharingConfiguration": {"Strategy": "RESERVE"},
                    "PreemptionConfiguration": {"InSharePreemption": "DISABLED"},
                },
                "DependsOn": ["JQ"],
            },
        },
        "Outputs": {
            "SpRef": {"Value": {"Ref": "SP"}},
            "SeRef": {"Value": {"Ref": "SE"}},
            "SeArnAtt": {"Value": {"Fn::GetAtt": ["SE", "ServiceEnvironmentArn"]}},
            "QsRef": {"Value": {"Ref": "QS"}},
            "QsArnAtt": {"Value": {"Fn::GetAtt": ["QS", "QuotaShareArn"]}},
            "JqRef": {"Value": {"Ref": "JQ"}},
        },
    })


def _disable(batch, names: dict[str, str]) -> None:
    """Disable the quota share, job queue and service environment so the stack delete can remove them.

    Batch deletes each only once DISABLED; a resource Batch does not list, or lists as DELETED, is
    skipped.
    """
    queues = [q for q in batch.describe_job_queues(jobQueues=[names["jq"]])["jobQueues"]
              if q["status"] != "DELETED"]
    if queues:
        for share in paginate(batch, "list_quota_shares", "quotaShares", jobQueue=names["jq"]):
            if share["quotaShareName"] == names["qs"] and share["state"] != "DISABLED":
                arn = share["quotaShareArn"]
                batch.update_quota_share(quotaShareArn=arn, state="DISABLED")
                _poll(lambda: batch.describe_quota_share(quotaShareArn=arn),
                      lambda d: (d["status"], d["state"]) == ("VALID", "DISABLED"))
        if queues[0]["state"] != "DISABLED":
            batch.update_job_queue(jobQueue=names["jq"], state="DISABLED")
            _poll(lambda: batch.describe_job_queues(jobQueues=[names["jq"]])["jobQueues"][0],
                  lambda q: (q["status"], q["state"]) == ("VALID", "DISABLED"))
    envs = batch.describe_service_environments(
        serviceEnvironments=[names["se"]])["serviceEnvironments"]
    if envs and envs[0]["status"] != "DELETED" and envs[0]["state"] != "DISABLED":
        batch.update_service_environment(serviceEnvironment=names["se"], state="DISABLED")
        _poll(lambda: batch.describe_service_environments(
            serviceEnvironments=[names["se"]])["serviceEnvironments"][0],
            lambda s: (s["status"], s["state"]) == ("VALID", "DISABLED"))


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:deploy", "plane:control")
def run(ctx) -> None:
    """A CloudFormation Batch ServiceEnvironment, JobQueue, SchedulingPolicy and QuotaShare read back.

    Each Ref and ARN matches what Batch describes, with every templated property; once disabled,
    the stack delete leaves Batch describing none of them.
    """
    cfn = ctx.client("cloudformation")
    batch = ctx.client("batch")
    names = {key: ctx.unique_name(f"sim2real-batch-se-{key}-") for key in ("sp", "se", "jq", "qs")}

    stack_id = create_stack(ctx, cfn, ctx.unique_name("sim2real-batch-se-stack-"),
                            _template(names))
    ctx.on_cleanup(lambda: _disable(batch, names))
    status = wait_stack(cfn, stack_id)
    assert status == "CREATE_COMPLETE", (
        f"stack ended {status!r}: {decisive_rows(stack_events(cfn, stack_id))!r}"
    )
    out = stack_outputs(cfn, stack_id)
    se_arn, qs_arn, jq_arn, sp_arn = out["SeRef"], out["QsRef"], out["JqRef"], out["SpRef"]
    assert (out["SeArnAtt"], out["QsArnAtt"]) == (se_arn, qs_arn), f"GetAtt ARNs {out!r}"

    se = _poll(lambda: batch.describe_service_environments(
        serviceEnvironments=[names["se"]])["serviceEnvironments"],
        lambda found: [s["status"] for s in found] == ["VALID"])[0]
    got = (se["serviceEnvironmentArn"], se["serviceEnvironmentName"], se["serviceEnvironmentType"],
           se["state"], se["capacityLimits"])
    want = (se_arn, names["se"], "SAGEMAKER_TRAINING", "ENABLED",
            [{"maxCapacity": 2, "capacityUnit": "ml.m6i.large"}])
    assert got == want, f"service environment reads {got!r}, expected {want!r}"

    jq = _poll(lambda: batch.describe_job_queues(jobQueues=[names["jq"]])["jobQueues"],
               lambda found: [q["status"] for q in found] == ["VALID"])[0]
    got = (jq["jobQueueArn"], jq["jobQueueType"], jq["priority"], jq["schedulingPolicyArn"],
           jq["serviceEnvironmentOrder"])
    want = (jq_arn, "SAGEMAKER_TRAINING", 1, sp_arn, [{"order": 1, "serviceEnvironment": se_arn}])
    assert got == want, f"job queue reads {got!r}, expected {want!r}"

    sp = batch.describe_scheduling_policies(arns=[sp_arn])["schedulingPolicies"]
    got = [(p["name"], p["quotaSharePolicy"]) for p in sp]
    want = [(names["sp"], {"idleResourceAssignmentStrategy": "FIFO"})]
    assert got == want, f"scheduling policy reads {got!r}, expected {want!r}"

    shares = paginate(batch, "list_quota_shares", "quotaShares", jobQueue=names["jq"])
    assert [s["quotaShareArn"] for s in shares] == [qs_arn], f"quota shares {shares!r}"
    qs = _poll(lambda: batch.describe_quota_share(quotaShareArn=qs_arn),
               lambda q: q["status"] == "VALID")
    got = (qs["quotaShareName"], qs["jobQueueArn"], qs["state"], qs["capacityLimits"],
           qs["resourceSharingConfiguration"], qs["preemptionConfiguration"])
    want = (names["qs"], jq_arn, "ENABLED", [{"maxCapacity": 1, "capacityUnit": "ml.m6i.large"}],
            {"strategy": "RESERVE"}, {"inSharePreemption": "DISABLED"})
    assert got == want, f"quota share reads {got!r}, expected {want!r}"

    _disable(batch, names)
    delete_stack(cfn, stack_id)
    refused = ("ClientException", f"{qs_arn} does not exist.")
    expect_error(lambda: batch.describe_quota_share(quotaShareArn=qs_arn), *refused)
    gone = (batch.describe_job_queues(jobQueues=[jq_arn])["jobQueues"],
            batch.describe_service_environments(serviceEnvironments=[se_arn])["serviceEnvironments"],
            batch.describe_scheduling_policies(arns=[sp_arn])["schedulingPolicies"])
    assert gone == ([], [], []), f"after the stack delete Batch describes {gone!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
