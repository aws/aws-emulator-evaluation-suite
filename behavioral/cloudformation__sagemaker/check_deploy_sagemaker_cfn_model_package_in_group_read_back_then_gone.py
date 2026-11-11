"""deploy-sagemaker-cfn-model-package-in-group-read-back-then-gone."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-sagemaker-cfn-model-package-in-group-read-back-then-gone"
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


def _delete_lineage_entity(sm, arn: str, delete) -> None:
    """Remove a Lineage entity's associations, which block its delete, then delete it.

    Neither DeleteModelPackageGroup nor DeleteModelPackage removes the Context/Action/Artifact
    SageMaker auto-creates for them, so each is a separate, independent delete.
    """
    linked: set[str] = set()
    for side in ("SourceArn", "DestinationArn"):
        other_side = "DestinationArn" if side == "SourceArn" else "SourceArn"
        for assoc in paginate(sm, "list_associations", "AssociationSummaries", **{side: arn}):
            linked.add(assoc[other_side])
            sm.delete_association(SourceArn=assoc["SourceArn"], DestinationArn=assoc["DestinationArn"])
    try:
        delete()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFound":
            raise
    for other_arn in linked:
        if ":artifact/" in other_arn:
            _delete_lineage_entity(sm, other_arn, lambda a=other_arn: sm.delete_artifact(ArtifactArn=a))


def _delete_lineage_context(sm, source_uri: str) -> None:
    """Delete the Lineage Context SageMaker auto-creates for a Model Package Group."""
    for context in paginate(sm, "list_contexts", "ContextSummaries", SourceUri=source_uri):
        _delete_lineage_entity(
            sm, context["ContextArn"], lambda n=context["ContextName"]: sm.delete_context(ContextName=n)
        )


def _delete_lineage_action(sm, source_uri: str) -> None:
    """Delete the Lineage Action SageMaker auto-creates for a Model Package version."""
    for action in paginate(sm, "list_actions", "ActionSummaries", SourceUri=source_uri):
        _delete_lineage_entity(
            sm, action["ActionArn"], lambda n=action["ActionName"]: sm.delete_action(ActionName=n)
        )


@tags("axis:happy-path", "cap:c1", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A CloudFormation SageMaker model package versioned into its group reads back exactly.

    Ref and GetAtt match the listed version and its inference spec reads back; an update dropping
    the package removes it while the group answers, and the stack delete removes the group.
    """
    cfn = ctx.client("cloudformation")
    sm = ctx.client("sagemaker")
    stack_name = ctx.unique_name("sim2real-behav-cfn-smmp-")
    group_name = ctx.unique_name("sim2real-mpg-ver-")
    image = _builtin_image(ctx.region)
    content_type = "text/csv"
    response_mime_type = "text/csv"

    def template(with_package=True):
        resources = {
            "ModelGroup": {
                "Type": "AWS::SageMaker::ModelPackageGroup",
                "Properties": {"ModelPackageGroupName": group_name,
                               "Tags": [{"Key": "sim2real", "Value": stack_name}]},
            },
        }
        outputs = {"GroupRef": {"Value": {"Ref": "ModelGroup"}}}
        if with_package:
            resources["ModelPackage"] = {
                "Type": "AWS::SageMaker::ModelPackage",
                "DependsOn": "ModelGroup",
                "Properties": {
                    "ModelPackageGroupName": group_name,
                    "InferenceSpecification": {
                        "Containers": [{"Image": image}],
                        "SupportedContentTypes": [content_type],
                        "SupportedResponseMIMETypes": [response_mime_type],
                    },
                },
            }
            outputs["PackageRef"] = {"Value": {"Ref": "ModelPackage"}}
            outputs["PackageStatus"] = {
                "Value": {"Fn::GetAtt": ["ModelPackage", "ModelPackageStatus"]}
            }
        return json.dumps({"AWSTemplateFormatVersion": "2010-09-09", "Resources": resources,
                           "Outputs": outputs})

    # No stack-level Tags: CloudFormation forwards them onto every taggable resource, and a
    # model package version refuses Tags. The group carries its own sim2real tag instead.
    # Cleanup first, as create_stack does: a stack AWS accepted is deleted even if the call raises.
    created = {}
    ctx.on_cleanup(lambda: delete_stack_named(cfn, stack_name, created.get("StackId")))
    stack_id = cfn.create_stack(StackName=stack_name, TemplateBody=template())["StackId"]
    created["StackId"] = stack_id
    status = wait_stack(cfn, stack_id)
    assert status == "CREATE_COMPLETE", (
        f"stack ended {status!r}: {decisive_rows(stack_events(cfn, stack_id))!r}"
    )
    outputs = stack_outputs(cfn, stack_id)

    # Group: Ref == the ARN an independent ListModelPackageGroups reports for the name.
    groups = [g["ModelPackageGroupArn"] for g in paginate(
        sm, "list_model_package_groups", "ModelPackageGroupSummaryList", NameContains=group_name)
        if g["ModelPackageGroupName"] == group_name]
    assert groups == [outputs["GroupRef"]], f"ListModelPackageGroups found {groups!r}"
    group = sm.describe_model_package_group(ModelPackageGroupName=group_name)
    ctx.on_cleanup(lambda: _delete_lineage_context(sm, group["ModelPackageGroupArn"]))
    assert group["ModelPackageGroupStatus"] == "Completed", (
        f"expected group Completed, got {group['ModelPackageGroupStatus']!r}"
    )
    group_created = group["CreationTime"]
    group_tags = {t["Key"]: t["Value"] for t in paginate(
        sm, "list_tags", "Tags", ResourceArn=group["ModelPackageGroupArn"])
        if not t["Key"].startswith("aws:")}
    assert group_tags == {"sim2real": stack_name}, f"model package group tags {group_tags!r}"

    # Package: Ref == the one version ListModelPackages reports in the group.
    versions = [v["ModelPackageArn"] for v in paginate(
        sm, "list_model_packages", "ModelPackageSummaryList", ModelPackageGroupName=group_name)]
    assert versions == [outputs["PackageRef"]], (
        f"ListModelPackages found {versions!r}, Ref {outputs['PackageRef']!r}"
    )
    pkg = sm.describe_model_package(ModelPackageName=versions[0])
    ctx.on_cleanup(lambda: _delete_lineage_action(sm, pkg["ModelPackageArn"]))
    assert outputs["PackageStatus"] == pkg["ModelPackageStatus"] == "Completed", (
        f"GetAtt {outputs['PackageStatus']!r}, describe {pkg['ModelPackageStatus']!r}"
    )
    spec = pkg["InferenceSpecification"]
    got = (pkg["ModelPackageGroupName"], [c["Image"] for c in spec["Containers"]],
           spec["SupportedContentTypes"], spec["SupportedResponseMIMETypes"])
    want = (group_name, [image], [content_type], [response_mime_type])
    assert got == want, f"model package reads {got!r}, expected {want!r}"

    # Child first: an update dropping the package removes it while the same group answers.
    cfn.update_stack(StackName=stack_id, TemplateBody=template(with_package=False))
    status = wait_stack(cfn, stack_id)
    assert status == "UPDATE_COMPLETE", f"package-dropping update ended {status!r}"
    package = outputs["PackageRef"]
    until_raises(lambda: sm.describe_model_package(ModelPackageName=package))
    gone = ("ValidationException", f"ModelPackage {package} does not exist.")
    expect_error(lambda: sm.describe_model_package(ModelPackageName=package), *gone)
    still = sm.describe_model_package_group(ModelPackageGroupName=group_name)
    assert still["CreationTime"] == group_created, f"group after the update reads {still!r}"

    delete_stack(cfn, stack_id)
    until_raises(lambda: sm.describe_model_package_group(ModelPackageGroupName=group_name))
    gone = ("ValidationException", f"ModelPackageGroup {outputs['GroupRef']} does not exist.")
    expect_error(lambda: sm.describe_model_package_group(ModelPackageGroupName=group_name), *gone)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
