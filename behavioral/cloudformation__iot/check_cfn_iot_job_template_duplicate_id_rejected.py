"""cfn-iot-job-template-duplicate-id-rejected."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "cfn-iot-job-template-duplicate-id-rejected"
GROUP = "deploy"
SERVICES = ["cloudformation", "iot"]

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


def validation_rows(cf, stack_id):
    """Sorted ``(logical id, ValidationName, Status, FailureMode, Reason, Path)`` rows."""
    return sorted(
        (e.get("LogicalResourceId"), e.get("ValidationName"), e.get("ValidationStatus"),
         e.get("ValidationFailureMode"), e.get("ValidationStatusReason"), e.get("ValidationPath"))
        for e in paginate(cf, "describe_events", "OperationEvents", StackName=stack_id)
        if e.get("EventType") == "VALIDATION_ERROR"
    )


# ---- Check-specific: the template, then run(). ----

def _template(template_id: str, description: str, document: str) -> str:
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "JobTemplate": {
                "Type": "AWS::IoT::JobTemplate",
                "Properties": {
                    "JobTemplateId": template_id,
                    "Description": description,
                    "Document": document,
                },
            }
        },
        "Outputs": {
            "TemplateRef": {"Value": {"Ref": "JobTemplate"}},
            "TemplateArn": {"Value": {"Fn::GetAtt": ["JobTemplate", "Arn"]}},
        },
    })


def _listed(iot, template_id: str) -> list[tuple[str, str]]:
    """(id, ARN) of the job templates IoT lists under ``template_id``, every page."""
    return [(t["jobTemplateId"], t["jobTemplateArn"])
            for t in paginate(iot, "list_job_templates", "jobTemplates")
            if t["jobTemplateId"] == template_id]


def _snapshot(iot, template_id: str) -> tuple:
    t = iot.describe_job_template(jobTemplateId=template_id)
    return t["jobTemplateArn"], t["createdAt"], t["description"], t["document"]


@tags("axis:rejection", "cap:c3", "concern:deploy", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A CloudFormation AWS::IoT::JobTemplate reusing an existing JobTemplateId fails validation.

    The pre-existing template (same ARN and creation time) is untouched, while the same template
    under a fresh id deploys and reads back.
    """
    iot = ctx.client("iot")
    cfn = ctx.client("cloudformation")
    tag_value = ctx.unique_name("sim2real-jt-")
    existing_id = ctx.unique_name("sim2real-jt-")
    iot.create_job_template(
        jobTemplateId=existing_id, description="pre-existing job template",
        document=json.dumps({"version": "1.0", "steps": [{"action": {"name": "existing"}}]}),
        tags=[{"Key": "sim2real", "Value": tag_value}],
    )
    ctx.on_cleanup(lambda: iot.delete_job_template(jobTemplateId=existing_id))
    before = _snapshot(iot, existing_id)

    description = "conflicting description"
    document = json.dumps({"version": "1.0", "steps": [{"action": {"name": "conflict"}}]})
    fresh_id = ctx.unique_name("sim2real-jt-")
    good_id = create_stack(ctx, cfn, ctx.unique_name("sim2real-jt-stack-"),
                           _template(fresh_id, description, document))
    bad_id = create_stack(ctx, cfn, ctx.unique_name("sim2real-jt-stack-"),
                          _template(existing_id, description, document))
    status = wait_stack(cfn, bad_id)
    assert status == "ROLLBACK_COMPLETE", f"rejected stack ended {status!r}"
    rows = [r for r in validation_rows(cfn, bad_id) if r[3] == "FAIL"]
    want = [("JobTemplate", "NAME_CONFLICT_VALIDATION", "FAILED", "FAIL",
             f"Resource of type 'AWS::IoT::JobTemplate' with identifier '{existing_id}' "
             "already exists.", "/Resources/JobTemplate")]
    assert rows == want, f"validation rows {rows!r}, expected {want!r}"
    resources = cfn.list_stack_resources(StackName=bad_id)["StackResourceSummaries"]
    assert resources == [], f"a stack rejected before provisioning reports {resources!r}"
    after = _snapshot(iot, existing_id)
    assert after == before, f"the pre-existing template changed: {before!r} -> {after!r}"

    # Positive control: same template, the one property given a VALID value.
    status = wait_stack(cfn, good_id)
    assert status == "CREATE_COMPLETE", (
        f"control stack ended {status!r}: {decisive_rows(stack_events(cfn, good_id))!r}"
    )
    outputs = stack_outputs(cfn, good_id)
    listed = _listed(iot, fresh_id)
    assert listed == [(outputs["TemplateRef"], outputs["TemplateArn"])], (
        f"IoT lists {listed!r} for the control; Ref/GetAtt are {outputs!r}"
    )
    control = iot.describe_job_template(jobTemplateId=fresh_id)
    got = (control["jobTemplateId"], control["description"], control["document"])
    assert got == (fresh_id, description, document), f"the control template reads {got!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
