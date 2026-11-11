"""deploy-compute-environment-and-job-queue-lifecycle."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "deploy-compute-environment-and-job-queue-lifecycle"
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


def _template(ce_name: str, jq_name: str, subnet_ids: list, sg_id: str) -> str:
    return json.dumps({
        "Resources": {
            "CE": {
                "Type": "AWS::Batch::ComputeEnvironment",
                "Properties": {
                    "ComputeEnvironmentName": ce_name,
                    "Type": "MANAGED",
                    "ComputeResources": {
                        "Type": "FARGATE",
                        "MaxvCpus": 2,
                        "Subnets": subnet_ids,
                        "SecurityGroupIds": [sg_id],
                    },
                },
            },
            "JQ": {
                "Type": "AWS::Batch::JobQueue",
                "Properties": {
                    "JobQueueName": jq_name,
                    "Priority": 1,
                    "ComputeEnvironmentOrder": [{"Order": 1, "ComputeEnvironment": {"Ref": "CE"}}],
                },
            },
        },
        "Outputs": {
            "CeRef": {"Value": {"Ref": "CE"}},
            "CeArnAtt": {"Value": {"Fn::GetAtt": ["CE", "ComputeEnvironmentArn"]}},
            "JqRef": {"Value": {"Ref": "JQ"}},
            "JqArnAtt": {"Value": {"Fn::GetAtt": ["JQ", "JobQueueArn"]}},
        },
    })


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:deploy", "plane:control")
def run(ctx) -> None:
    """A CloudFormation Fargate ComputeEnvironment and JobQueue read back through Batch, then delete.

    Each Ref and ARN is the one Batch lists under the templated name, with every templated
    property; after the stack delete Batch lists neither ARN.
    """
    cfn = ctx.client("cloudformation")
    batch = ctx.client("batch")
    network = ctx.network()
    ce_name = ctx.unique_name("sim2real-batch-ce-")
    jq_name = ctx.unique_name("sim2real-batch-jq-")
    subnet_ids, sg_id = network.subnet_ids, network.security_group_id

    stack_id = create_stack(ctx, cfn, ctx.unique_name("sim2real-batch-cejq-stack-"),
                            _template(ce_name, jq_name, subnet_ids, sg_id))
    status = wait_stack(cfn, stack_id, timeout_s=600.0)
    assert status == "CREATE_COMPLETE", (
        f"stack ended {status!r}: {decisive_rows(stack_events(cfn, stack_id))!r}"
    )
    out = stack_outputs(cfn, stack_id)
    ce_arn, jq_arn = out["CeRef"], out["JqRef"]
    assert (out["CeArnAtt"], out["JqArnAtt"]) == (ce_arn, jq_arn), f"GetAtt ARNs {out!r}"

    # Refs against Batch's own listings by the templated names.
    ces = _poll(lambda: [c for c in paginate(batch, "describe_compute_environments",
                                             "computeEnvironments")
                         if c["computeEnvironmentName"] == ce_name],
                lambda found: [c["status"] for c in found] == ["VALID"])
    ce = ces[0]
    res = ce["computeResources"]
    got = (ce["computeEnvironmentArn"], ce["type"], res["type"], res["maxvCpus"],
           sorted(res["subnets"]), res["securityGroupIds"])
    want = (ce_arn, "MANAGED", "FARGATE", 2, sorted(subnet_ids), [sg_id])
    assert got == want, f"compute environment reads {got!r}, expected {want!r}"
    jqs = _poll(lambda: [q for q in paginate(batch, "describe_job_queues", "jobQueues")
                         if q["jobQueueName"] == jq_name],
                lambda found: [q["status"] for q in found] == ["VALID"])
    jq = jqs[0]
    got = (jq["jobQueueArn"], jq["priority"], jq["state"], jq["computeEnvironmentOrder"])
    want = (jq_arn, 1, "ENABLED", [{"order": 1, "computeEnvironment": ce_arn}])
    assert got == want, f"job queue reads {got!r}, expected {want!r}"

    delete_stack(cfn, stack_id)
    gone_jq = batch.describe_job_queues(jobQueues=[jq_arn])["jobQueues"]
    gone_ce = batch.describe_compute_environments(computeEnvironments=[ce_arn])["computeEnvironments"]
    assert (gone_jq, gone_ce) == ([], []), f"after the stack delete Batch lists {gone_jq!r} {gone_ce!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
