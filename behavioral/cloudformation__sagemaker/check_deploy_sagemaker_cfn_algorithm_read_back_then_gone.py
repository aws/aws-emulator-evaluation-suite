"""deploy-sagemaker-cfn-algorithm-read-back-then-gone."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-sagemaker-cfn-algorithm-read-back-then-gone"
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


def until_raises(fn, timeout_s=90.0):
    """Poll ``fn()`` every 2 s until it raises a ClientError (an eventually consistent delete).

    Grade the error afterwards with expect_error; a success past the deadline fails.
    """
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            result = fn()
        except ClientError:
            return
        if time.monotonic() > deadline:
            raise AssertionError(f"still answering after {timeout_s:.0f}s: {result!r}")
        time.sleep(2)


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

_TRAINING_IMAGE_ACCOUNTS = {
    "us-east-1": "382416733822",
    "us-east-2": "404615174143",
    "us-west-1": "632365934929",
    "us-west-2": "174872318107",
}


def _builtin_image(region: str) -> str:
    """The AWS-owned linear-learner built-in algorithm image URI for ``region``."""
    assert region in _TRAINING_IMAGE_ACCOUNTS, (
        f"precondition: this check's _TRAINING_IMAGE_ACCOUNTS table has no linear-learner registry "
        f"for {region} (a limit of the check, not an AWS refusal); extend the table"
    )
    account = _TRAINING_IMAGE_ACCOUNTS[region]
    return f"{account}.dkr.ecr.{region}.amazonaws.com/linear-learner:1"


def _own_tags(sm, arn):
    """The resource's tags as {key: value}, without the ``aws:`` system tags."""
    rows = paginate(sm, "list_tags", "Tags", ResourceArn=arn)
    return {r["Key"]: r["Value"] for r in rows if not r["Key"].startswith("aws:")}


@tags("axis:happy-path", "cap:c1", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A CloudFormation SageMaker algorithm on a built-in training image reads back exactly.

    Ref and GetAtt are the listed ARN, the training specification and stack tag match, and the
    stack delete removes the algorithm.
    """
    cfn = ctx.client("cloudformation")
    sm = ctx.client("sagemaker")
    stack_name = ctx.unique_name("sim2real-behav-cfn-smalgo-")
    algo_name = ctx.unique_name("sim2real-algo-")
    image = _builtin_image(ctx.region)
    instance_type = "ml.m5.large"
    channel_name = "training"

    template = {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "Algorithm": {
                "Type": "AWS::SageMaker::Algorithm",
                "Properties": {
                    "AlgorithmName": algo_name,
                    "TrainingSpecification": {
                        "TrainingImage": image,
                        "SupportedTrainingInstanceTypes": [instance_type],
                        "TrainingChannels": [
                            {
                                "Name": channel_name,
                                "SupportedContentTypes": ["text/csv"],
                                "SupportedInputModes": ["File"],
                            }
                        ],
                    },
                },
            },
        },
        "Outputs": {
            "AlgorithmRef": {"Value": {"Ref": "Algorithm"}},
            "AlgorithmArn": {"Value": {"Fn::GetAtt": ["Algorithm", "AlgorithmArn"]}},
        },
    }

    stack_id = create_stack(ctx, cfn, stack_name, json.dumps(template))
    status = wait_stack(cfn, stack_id)
    assert status == "CREATE_COMPLETE", (
        f"stack ended {status!r}: {decisive_rows(stack_events(cfn, stack_id))!r}"
    )
    outputs = stack_outputs(cfn, stack_id)

    # Ref and GetAtt == the ARN an independent ListAlgorithms reports for the templated name.
    listed = [a["AlgorithmArn"] for a in paginate(sm, "list_algorithms", "AlgorithmSummaryList",
                                                  NameContains=algo_name)
              if a["AlgorithmName"] == algo_name]
    assert len(listed) == 1, f"ListAlgorithms found {listed!r} for {algo_name!r}"
    assert (outputs["AlgorithmRef"], outputs["AlgorithmArn"]) == (listed[0], listed[0]), (
        f"Ref {outputs['AlgorithmRef']!r}, GetAtt {outputs['AlgorithmArn']!r}, "
        f"listed {listed[0]!r}"
    )

    algo = sm.describe_algorithm(AlgorithmName=algo_name)
    assert (algo["AlgorithmArn"], algo["AlgorithmStatus"]) == (listed[0], "Completed"), (
        f"DescribeAlgorithm reads {algo['AlgorithmArn']!r}, {algo['AlgorithmStatus']!r}"
    )
    spec = algo["TrainingSpecification"]
    got = (spec["TrainingImage"], spec["SupportedTrainingInstanceTypes"],
           [(c["Name"], c["SupportedContentTypes"], c["SupportedInputModes"])
            for c in spec["TrainingChannels"]])
    want = (image, [instance_type], [(channel_name, ["text/csv"], ["File"])])
    assert got == want, f"training specification reads {got!r}, expected {want!r}"
    algo_tags = _own_tags(sm, listed[0])
    assert algo_tags == {"sim2real": stack_name}, f"algorithm tags {algo_tags!r}"

    delete_stack(cfn, stack_id)
    until_raises(lambda: sm.describe_algorithm(AlgorithmName=algo_name))
    gone = ("ValidationException", f"Algorithm {listed[0]} does not exist.")
    expect_error(lambda: sm.describe_algorithm(AlgorithmName=algo_name), *gone)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
