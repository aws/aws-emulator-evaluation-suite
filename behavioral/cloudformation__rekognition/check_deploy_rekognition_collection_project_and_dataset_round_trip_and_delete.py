"""deploy-rekognition-collection-project-and-dataset-round-trip-and-delete."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-rekognition-collection-project-and-dataset-round-trip-and-delete"
GROUP = "deploy"
SERVICES = ["cloudformation", "rekognition"]

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

def _template(collection_id: str, project_name: str, with_dataset: bool = True) -> str:
    resources = {
        "Coll": {"Type": "AWS::Rekognition::Collection",
                 "Properties": {"CollectionId": collection_id}},
        "Proj": {"Type": "AWS::Rekognition::Project",
                 "Properties": {"ProjectName": project_name}},
    }
    outputs = {
        "CollId": {"Value": {"Ref": "Coll"}},
        "CollArn": {"Value": {"Fn::GetAtt": ["Coll", "Arn"]}},
        "ProjName": {"Value": {"Ref": "Proj"}},
        "ProjArn": {"Value": {"Fn::GetAtt": ["Proj", "Arn"]}},
    }
    if with_dataset:
        resources["Ds"] = {"Type": "AWS::Rekognition::Dataset",
                           "Properties": {"ProjectArn": {"Fn::GetAtt": ["Proj", "Arn"]},
                                          "DatasetType": "TRAIN"}}
        outputs["DsArn"] = {"Value": {"Ref": "Ds"}}
    return json.dumps({"AWSTemplateFormatVersion": "2010-09-09", "Resources": resources,
                       "Outputs": outputs})


def _project(rek, name):
    rows = paginate(rek, "describe_projects", "ProjectDescriptions", ProjectNames=[name])
    assert len(rows) == 1, f"expected one project named {name!r}, got {rows!r}"
    return rows[0]


@tags("axis:happy-path", "cap:c1", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A CloudFormation AWS::Rekognition::Collection, Project and Dataset reach Rekognition's
    CREATED/CREATE_COMPLETE state with the declared ids; an update dropping the dataset removes it
    while its project stays, and the stack delete removes the collection and project.

    Reference: https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-rekognition-collection.html
    Reference: https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-rekognition-project.html
    Reference: https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-rekognition-dataset.html
    """
    rek = ctx.client("rekognition")
    cfn = ctx.client("cloudformation")
    collection_id = ctx.unique_name("sim2real-rekcoll-")
    project_name = ctx.unique_name("sim2real-rekproj-")

    stack_id = create_stack(ctx, cfn, ctx.unique_name("sim2real-rekcpd-"),
                            _template(collection_id, project_name))
    status = wait_stack(cfn, stack_id)
    assert status == "CREATE_COMPLETE", (
        f"stack ended {status!r}: {decisive_rows(stack_events(cfn, stack_id))!r}"
    )
    out = stack_outputs(cfn, stack_id)
    partition = stack_id.split(":")[1]

    listed = [c for c in paginate(rek, "list_collections", "CollectionIds") if c == collection_id]
    assert listed == [out["CollId"]] == [collection_id], (
        f"ListCollections {listed!r}, Ref {out['CollId']!r}"
    )
    want_arn = f"arn:{partition}:rekognition:{ctx.region}:{ctx.account}:collection/{collection_id}"
    got = (rek.describe_collection(CollectionId=collection_id)["CollectionARN"], out["CollArn"])
    assert got == (want_arn, want_arn), f"CollectionARN / GetAtt Arn {got!r}, expected {want_arn!r}"

    assert out["ProjName"] == project_name, f"Project Ref {out['ProjName']!r}"
    project = _project(rek, project_name)
    got = (project["ProjectArn"], project["Status"])
    assert got == (out["ProjArn"], "CREATED"), f"project (arn, status) {got!r}"
    datasets = [(d["DatasetArn"], d["DatasetType"], d["Status"]) for d in project["Datasets"]]
    assert datasets == [(out["DsArn"], "TRAIN", "CREATE_COMPLETE")], (
        f"the project's datasets {datasets!r}"
    )
    direct = rek.describe_dataset(DatasetArn=out["DsArn"])["DatasetDescription"]
    assert direct["Status"] == "CREATE_COMPLETE", f"DescribeDataset Status {direct['Status']!r}"

    # The dataset's own delete: an update dropping it while its project still answers.
    cfn.update_stack(StackName=stack_id,
                     TemplateBody=_template(collection_id, project_name, with_dataset=False))
    status = wait_stack(cfn, stack_id)
    assert status == "UPDATE_COMPLETE", f"dataset-removing update ended {status!r}"
    until_raises(lambda: rek.describe_dataset(DatasetArn=out["DsArn"]))
    expect_error(lambda: rek.describe_dataset(DatasetArn=out["DsArn"]),
                 *("ResourceNotFoundException",
                   f"The dataset {out['DsArn']} doesn't exist. Check that the dataset exists."))
    project = _project(rek, project_name)
    assert (project["Status"], project.get("Datasets", [])) == ("CREATED", []), (
        f"the project after the dataset update reads {project!r}"
    )

    delete_stack(cfn, stack_id)
    expect_error(lambda: rek.describe_collection(CollectionId=collection_id),
                 *("ResourceNotFoundException", f"Collection:{collection_id} not found!"))
    remaining = paginate(rek, "describe_projects", "ProjectDescriptions",
                         ProjectNames=[project_name])
    assert remaining == [], f"after the stack delete the project still lists {remaining!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
