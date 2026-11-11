"""deploy-cloudformation-sagemaker-experiment-and-trial-component-round-trip-and-delete."""
from __future__ import annotations

import datetime
import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-cloudformation-sagemaker-experiment-and-trial-component-round-trip-and-delete"
GROUP = "deploy"
SERVICES = ["cloudformation", "sagemaker"]

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

def _parse_getatt_time(value: str) -> datetime.datetime:
    return datetime.datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%fZ").replace(
        tzinfo=datetime.timezone.utc
    )


def _template(experiment_name, experiment_display_name, experiment_description,
              trial_component_name, trial_component_display_name):
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "Exp": {
                "Type": "AWS::SageMaker::Experiment",
                "Properties": {
                    "ExperimentName": experiment_name,
                    "DisplayName": experiment_display_name,
                    "Description": experiment_description,
                    "Tags": [{"Key": "sim2real-exp", "Value": experiment_name}],
                },
            },
            "Tc": {
                "Type": "AWS::SageMaker::TrialComponent",
                "Properties": {
                    "TrialComponentName": trial_component_name,
                    "DisplayName": trial_component_display_name,
                    "Status": {"PrimaryStatus": "InProgress"},
                    "Tags": [{"Key": "sim2real-tc", "Value": trial_component_name}],
                },
            },
        },
        "Outputs": {
            "ExperimentArn": {"Value": {"Ref": "Exp"}},
            "ExperimentCreationTime": {"Value": {"Fn::GetAtt": ["Exp", "CreationTime"]}},
            "TrialComponentArn": {"Value": {"Ref": "Tc"}},
            "TrialComponentCreationTime": {"Value": {"Fn::GetAtt": ["Tc", "CreationTime"]}},
        },
    })


def _tags(sm, arn):
    return {t["Key"]: t["Value"] for t in paginate(sm, "list_tags", "Tags", ResourceArn=arn)
            if not t["Key"].startswith("aws:")}


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:deploy", "concern:representation",
      "plane:control")
def run(ctx) -> None:
    """CloudFormation-provisioned AWS::SageMaker::Experiment and ::TrialComponent each reach
    SageMaker with the declared names, description, status, tags and Ref/GetAtt values; deleting
    the stack removes both from SageMaker.
    """
    cfn = ctx.client("cloudformation")
    sm = ctx.client("sagemaker")
    stack = ctx.unique_name("sim2real-cfn-exptc-")
    experiment_name = ctx.unique_name("sim2real-experiment-")
    experiment_display_name = ctx.unique_name("sim2real-exp-display-")
    experiment_description = ctx.unique_name("sim2real-exp-desc-")
    trial_component_name = ctx.unique_name("sim2real-trialcomponent-")
    trial_component_display_name = ctx.unique_name("sim2real-tc-display-")

    stack_id = create_stack(
        ctx, cfn, stack,
        _template(experiment_name, experiment_display_name, experiment_description,
                  trial_component_name, trial_component_display_name),
    )
    status = wait_stack(cfn, stack_id)
    assert status == "CREATE_COMPLETE", (
        f"stack ended {status!r}: {decisive_rows(stack_events(cfn, stack_id))!r}"
    )
    outputs = stack_outputs(cfn, stack_id)
    partition = stack_id.split(":")[1]
    prefix = f"arn:{partition}:sagemaker:{ctx.region}:{ctx.account}"
    exp_arn = f"{prefix}:experiment/{experiment_name}"
    tc_arn = f"{prefix}:experiment-trial-component/{trial_component_name}"

    experiment = sm.describe_experiment(ExperimentName=experiment_name)
    got = (outputs["ExperimentArn"], experiment["ExperimentArn"], experiment.get("DisplayName"),
           experiment.get("Description"))
    want = (exp_arn, exp_arn, experiment_display_name, experiment_description)
    assert got == want, f"experiment (Ref, Arn, DisplayName, Description) {got!r} != {want!r}"
    assert experiment["CreationTime"] == _parse_getatt_time(outputs["ExperimentCreationTime"]), (
        f"GetAtt CreationTime {outputs['ExperimentCreationTime']!r} != DescribeExperiment "
        f"CreationTime {experiment['CreationTime']!r}"
    )
    exp_tags = _tags(sm, exp_arn)
    assert exp_tags == {"sim2real": stack, "sim2real-exp": experiment_name}, (
        f"experiment tags {exp_tags!r}"
    )

    trial_component = sm.describe_trial_component(TrialComponentName=trial_component_name)
    got = (outputs["TrialComponentArn"], trial_component["TrialComponentArn"],
           trial_component.get("DisplayName"), trial_component["Status"].get("PrimaryStatus"))
    want = (tc_arn, tc_arn, trial_component_display_name, "InProgress")
    assert got == want, f"trial component (Ref, Arn, DisplayName, Status) {got!r} != {want!r}"
    assert trial_component["CreationTime"] == _parse_getatt_time(
        outputs["TrialComponentCreationTime"]
    ), (
        f"GetAtt CreationTime {outputs['TrialComponentCreationTime']!r} != "
        f"DescribeTrialComponent CreationTime {trial_component['CreationTime']!r}"
    )
    tc_tags = _tags(sm, tc_arn)
    assert tc_tags == {"sim2real": stack, "sim2real-tc": trial_component_name}, (
        f"trial component tags {tc_tags!r}"
    )

    delete_stack(cfn, stack_id)
    gone = ("ResourceNotFound", f"Experiment '{exp_arn}' does not exist.")
    expect_error(lambda: sm.describe_experiment(ExperimentName=experiment_name), *gone)
    gone = ("ResourceNotFound", f"Trial component '{tc_arn}' does not exist.")
    expect_error(lambda: sm.describe_trial_component(TrialComponentName=trial_component_name),
                 *gone)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
