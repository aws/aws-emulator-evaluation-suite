"""deploy-databrew-dataset-and-ruleset-round-trip-and-delete."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-databrew-dataset-and-ruleset-round-trip-and-delete"
GROUP = "deploy"
SERVICES = ["cloudformation", "databrew"]

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

_OBJECT_KEY = "data.csv"
_CHECK_EXPRESSION = "AGG(DUPLICATE_ROWS_COUNT) < :val"
_THRESHOLD = "100"


def _template(bucket_name: str, dataset_name: str, ruleset_name: str,
              with_ruleset: bool = True) -> str:
    """Template tags use a key the propagated stack tag lacks."""
    resources = {
        "Bucket": {"Type": "AWS::S3::Bucket", "Properties": {"BucketName": bucket_name}},
        "Dataset": {"Type": "AWS::DataBrew::Dataset", "Properties": {
            "Name": dataset_name,
            "Input": {"S3InputDefinition": {"Bucket": {"Ref": "Bucket"}, "Key": _OBJECT_KEY}},
            "Tags": [{"Key": "sim2real-ds", "Value": dataset_name}],
        }},
    }
    outputs = {
        "BucketRef": {"Value": {"Ref": "Bucket"}},
        "DatasetRef": {"Value": {"Ref": "Dataset"}},
    }
    if with_ruleset:
        resources["Ruleset"] = {"Type": "AWS::DataBrew::Ruleset", "Properties": {
            "Name": ruleset_name,
            "TargetArn": {"Fn::Sub": "arn:${AWS::Partition}:databrew:${AWS::Region}:"
                                     "${AWS::AccountId}:dataset/${Dataset}"},
            "Rules": [{"Name": "rule1", "CheckExpression": _CHECK_EXPRESSION,
                       "SubstitutionMap": [{"ValueReference": ":val", "Value": _THRESHOLD}]}],
            "Tags": [{"Key": "sim2real-rs", "Value": ruleset_name}],
        }}
        outputs["RulesetRef"] = {"Value": {"Ref": "Ruleset"}}
    return json.dumps({"AWSTemplateFormatVersion": "2010-09-09", "Resources": resources,
                       "Outputs": outputs})


def _own_tags(tags_):
    return {k: v for k, v in (tags_ or {}).items() if not k.startswith("aws:")}


@tags("axis:happy-path", "cap:c1", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A CloudFormation DataBrew Dataset and Ruleset read back, then deleted child-first.

    Each Ref is a listed name and every templated property and tag reads back; dropping the ruleset
    removes it while the same dataset answers, then the stack delete removes the dataset.
    """
    cfn = ctx.client("cloudformation")
    db = ctx.client("databrew")
    stack = ctx.unique_name("sim2real-dbdsrs-")
    bucket_name = ctx.unique_name("sim2real-dbdsbkt-")
    dataset_name = ctx.unique_name("sim2real-dbdataset-")
    ruleset_name = ctx.unique_name("sim2real-dbruleset-")

    stack_id = create_stack(ctx, cfn, stack, _template(bucket_name, dataset_name, ruleset_name))
    status = wait_stack(cfn, stack_id)
    assert status == "CREATE_COMPLETE", (
        f"stack ended {status!r}: {decisive_rows(stack_events(cfn, stack_id))!r}"
    )
    out = stack_outputs(cfn, stack_id)
    partition = stack_id.split(":")[1]

    listed = [d["Name"] for d in paginate(db, "list_datasets", "Datasets") if d["Name"] == dataset_name]
    assert listed == [out["DatasetRef"]], f"ListDatasets named {dataset_name!r}: {listed!r}"
    dataset = db.describe_dataset(Name=dataset_name)
    got = (dataset["Name"], dataset["Input"]["S3InputDefinition"], _own_tags(dataset.get("Tags")))
    want = (dataset_name, {"Bucket": out["BucketRef"], "Key": _OBJECT_KEY},
            {"sim2real": stack, "sim2real-ds": dataset_name})
    assert got == want, f"DescribeDataset {got!r}, expected {want!r}"

    listed = [r["Name"] for r in paginate(db, "list_rulesets", "Rulesets") if r["Name"] == ruleset_name]
    assert listed == [out["RulesetRef"]], f"ListRulesets named {ruleset_name!r}: {listed!r}"
    ruleset = db.describe_ruleset(Name=ruleset_name)
    target = f"arn:{partition}:databrew:{ctx.region}:{ctx.account}:dataset/{dataset_name}"
    got = (ruleset["Name"], ruleset["TargetArn"],
           [(r["Name"], r["CheckExpression"], r["SubstitutionMap"]) for r in ruleset["Rules"]],
           _own_tags(ruleset.get("Tags")))
    want = (ruleset_name, target, [("rule1", _CHECK_EXPRESSION, {":val": _THRESHOLD})],
            {"sim2real": stack, "sim2real-rs": ruleset_name})
    assert got == want, f"DescribeRuleset {got!r}, expected {want!r}"

    # Child first: the update drops only the ruleset; its own NotFound while the same dataset
    # (CreateDate) still answers.
    cfn.update_stack(StackName=stack_id, TemplateBody=_template(
        bucket_name, dataset_name, ruleset_name, with_ruleset=False))
    status = wait_stack(cfn, stack_id)
    assert status == "UPDATE_COMPLETE", f"ruleset-dropping update ended {status!r}"
    ruleset_gone = ("ResourceNotFoundException", f"Ruleset {ruleset_name} wasn't found")
    expect_error(lambda: db.describe_ruleset(Name=ruleset_name), *ruleset_gone)
    kept = db.describe_dataset(Name=dataset_name)["CreateDate"]
    assert kept == dataset["CreateDate"], (
        f"dataset CreateDate {kept!r} after the update, was {dataset['CreateDate']!r}"
    )

    delete_stack(cfn, stack_id)
    dataset_gone = ("ResourceNotFoundException", f"Dataset {dataset_name} wasn't found.")
    expect_error(lambda: db.describe_dataset(Name=dataset_name), *dataset_gone)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
