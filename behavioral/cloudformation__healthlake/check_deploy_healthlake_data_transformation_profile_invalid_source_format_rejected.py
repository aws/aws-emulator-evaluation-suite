"""deploy-healthlake-data-transformation-profile-invalid-source-format-rejected."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "deploy-healthlake-data-transformation-profile-invalid-source-format-rejected"
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


def validation_rows(cf, stack_id):
    """Sorted ``(logical id, ValidationName, Status, FailureMode, Reason, Path)`` rows."""
    return sorted(
        (e.get("LogicalResourceId"), e.get("ValidationName"), e.get("ValidationStatus"),
         e.get("ValidationFailureMode"), e.get("ValidationStatusReason"), e.get("ValidationPath"))
        for e in paginate(cf, "describe_events", "OperationEvents", StackName=stack_id)
        if e.get("EventType") == "VALIDATION_ERROR"
    )


# ---- Check-specific: the template, then run(). ----

_MAPPING_CONTENT = "version: 1\nresourceType: Patient\n"


def _template(profile_name: str, description: str, source_format: str) -> str:
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "Profile": {
                "Type": "AWS::HealthLake::DataTransformationProfile",
                "Properties": {
                    "ProfileName": profile_name,
                    "SourceFormat": source_format,
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
        },
    })


@tags("axis:rejection", "cap:c3", "concern:deploy", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """An AWS::HealthLake::DataTransformationProfile with an out-of-enum SourceFormat is refused.

    Property validation fails and no profile is created, while the same template with CSV
    deploys a profile HealthLake lists and reads back with every templated property.

    Reference: https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-healthlake-datatransformationprofile.html
    """
    cfn = ctx.client("cloudformation")
    healthlake = ctx.client("healthlake")
    bad_name = ctx.unique_name("sim2real-hldtp-bad-")
    good_name = ctx.unique_name("sim2real-hldtp-good-")
    good_description = ctx.unique_name("sim2real-hldtp-good-desc-")

    good_id = create_stack(ctx, cfn, ctx.unique_name("sim2real-cfn-hldtp-good-"),
                           _template(good_name, good_description, "CSV"))
    bad_id = create_stack(ctx, cfn, ctx.unique_name("sim2real-cfn-hldtp-bad-"),
                          _template(bad_name, ctx.unique_name("sim2real-hldtp-bad-desc-"), "XML"))
    status = wait_stack(cfn, bad_id)
    assert status == "ROLLBACK_COMPLETE", f"rejected stack ended {status!r}"
    rows = validation_rows(cfn, bad_id)
    want = [("Profile", "PROPERTY_VALIDATION", "FAILED", "FAIL",
             "XML is not a valid enum value. Supported values: [CCDA, CSV]",
             "/Resources/Profile/Properties/SourceFormat")]
    assert rows == want, f"validation rows {rows!r}, expected {want!r}"
    resources = cfn.list_stack_resources(StackName=bad_id)["StackResourceSummaries"]
    assert resources == [], f"a stack rejected before provisioning reports {resources!r}"

    # Positive control: same template, the one property given a VALID value.
    status = wait_stack(cfn, good_id)
    assert status == "CREATE_COMPLETE", (
        f"control stack ended {status!r}: {decisive_rows(stack_events(cfn, good_id))!r}"
    )
    outputs = stack_outputs(cfn, good_id)
    listed = [p["ProfileId"] for p in paginate(healthlake, "list_data_transformation_profiles",
                                               "Items", SourceFormat="CSV")
              if p["ProfileName"] == good_name]
    assert listed == [outputs["ProfileId"]], f"HealthLake lists {listed!r} for the control"
    got = healthlake.get_data_transformation_profile(ProfileId=listed[0])
    got = {k: got.get(k) for k in ("ProfileName", "SourceFormat", "ProfileDescription",
                                    "ProfileMapping")}
    want = {"ProfileName": good_name, "SourceFormat": "CSV",
            "ProfileDescription": good_description,
            "ProfileMapping": {"mapping-config.yaml": _MAPPING_CONTENT}}
    assert got == want, f"control profile reads {got!r}, expected {want!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
