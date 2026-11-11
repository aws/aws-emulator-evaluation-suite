"""deploy-healthlake-data-transformation-profile-round-trip-and-delete."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-healthlake-data-transformation-profile-round-trip-and-delete"
GROUP = "deploy"
SERVICES = ["cloudformation", "healthlake"]

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

_MAPPING_CONTENT = "version: 1\nresourceType: Patient\n"


def _template(profile_name: str, description: str) -> str:
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "Profile": {
                "Type": "AWS::HealthLake::DataTransformationProfile",
                "Properties": {
                    "ProfileName": profile_name,
                    "SourceFormat": "CSV",
                    "ProfileDescription": description,
                    "Source": {
                        "ProfileMapping": {
                            "ProfileMapping": {"mapping-config.yaml": _MAPPING_CONTENT}
                        }
                    },
                    "Tags": [{"Key": "sim2real-hl", "Value": profile_name}],
                },
            }
        },
        "Outputs": {
            "ProfileArn": {"Value": {"Ref": "Profile"}},
            "ProfileId": {"Value": {"Fn::GetAtt": ["Profile", "ProfileId"]}},
            "TargetFormat": {"Value": {"Fn::GetAtt": ["Profile", "TargetFormat"]}},
        },
    })


def _listed(healthlake, profile_name: str) -> list[str]:
    """ProfileIds HealthLake lists (every CSV page) under ``profile_name``."""
    return [p["ProfileId"] for p in paginate(healthlake, "list_data_transformation_profiles",
                                             "Items", SourceFormat="CSV")
            if p["ProfileName"] == profile_name]


@tags("axis:happy-path", "cap:c3", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A CloudFormation AWS::HealthLake::DataTransformationProfile reads back through HealthLake.

    Ref and the GetAtts match the profile HealthLake lists by name with every templated property
    and tag, and after the stack delete HealthLake answers NotFound and lists it no more.

    Reference: https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-healthlake-datatransformationprofile.html
    """
    cfn = ctx.client("cloudformation")
    healthlake = ctx.client("healthlake")
    profile_name = ctx.unique_name("sim2real-hldtp-")
    description = ctx.unique_name("sim2real-hldtp-desc-")

    stack_id = create_stack(ctx, cfn, ctx.unique_name("sim2real-cfn-hldtp-"),
                            _template(profile_name, description))
    status = wait_stack(cfn, stack_id)
    assert status == "CREATE_COMPLETE", (
        f"stack ended {status!r}: {decisive_rows(stack_events(cfn, stack_id))!r}"
    )
    outputs = stack_outputs(cfn, stack_id)
    partition = stack_id.split(":")[1]

    # The GetAtt ProfileId against an independent read: the profile listed under its name.
    listed = _listed(healthlake, profile_name)
    assert listed == [outputs["ProfileId"]], (
        f"HealthLake lists {listed!r} for {profile_name!r}; GetAtt ProfileId {outputs['ProfileId']!r}"
    )
    profile_id = listed[0]
    want_arn = (
        f"arn:{partition}:healthlake:{ctx.region}:{ctx.account}:dataTransformationProfile/"
        f"{profile_id}"
    )
    assert outputs["ProfileArn"] == want_arn, f"Ref {outputs['ProfileArn']!r} != {want_arn!r}"

    got = healthlake.get_data_transformation_profile(ProfileId=profile_id)
    got = {k: got.get(k) for k in ("ProfileId", "ProfileName", "SourceFormat", "TargetFormat",
                                    "ProfileDescription", "ProfileMapping")}
    want = {"ProfileId": profile_id, "ProfileName": profile_name, "SourceFormat": "CSV",
            "TargetFormat": "FHIR_R4", "ProfileDescription": description,
            "ProfileMapping": {"mapping-config.yaml": _MAPPING_CONTENT}}
    assert got == want, f"GetDataTransformationProfile reads {got!r}, expected {want!r}"
    assert outputs["TargetFormat"] == "FHIR_R4", f"GetAtt TargetFormat {outputs['TargetFormat']!r}"
    found = {t["Key"]: t["Value"] for t in
             healthlake.list_tags_for_resource(ResourceARN=want_arn)["Tags"]
             if t["Key"] != "sim2real" and not t["Key"].startswith("aws:")}
    assert found == {"sim2real-hl": profile_name}, f"ListTagsForResource reports {found!r}"

    delete_stack(cfn, stack_id)
    expect_error(lambda: healthlake.get_data_transformation_profile(ProfileId=profile_id),
                 *("ResourceNotFoundException", f"Profile '{profile_id}' not found"))
    assert _listed(healthlake, profile_name) == [], "the deleted profile is still listed"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
