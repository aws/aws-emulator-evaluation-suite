"""deploy-cfn-datasync-location-object-storage-round-trip-and-delete."""
from __future__ import annotations

import json
import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-cfn-datasync-location-object-storage-round-trip-and-delete"
GROUP = "deploy"
SERVICES = ["cloudformation", "datasync"]

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


def _template(hostname: str, bucket_name: str) -> str:
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "Loc": {
                "Type": "AWS::DataSync::LocationObjectStorage",
                "Properties": {
                    "ServerHostname": hostname,
                    "BucketName": bucket_name,
                    "ServerProtocol": "HTTPS",
                },
            },
        },
        "Outputs": {
            "LocArn": {"Value": {"Ref": "Loc"}},
            "LocUri": {"Value": {"Fn::GetAtt": ["Loc", "LocationUri"]}},
        },
    })


def _location_arns_for_uri(ds, uri: str) -> list[str]:
    """Every listed location ARN whose LocationUri is ``uri``, read across all pages."""
    return [loc["LocationArn"]
            for page in ds.get_paginator("list_locations").paginate()
            for loc in page["Locations"] if loc["LocationUri"] == uri]


def _assert_location_ref(ctx, ds, loc_arn: str, uri: str) -> None:
    """Ref is a documented location ARN, and ListLocations lists exactly it for ``uri``."""
    pattern = (rf"arn:aws[a-z-]*:datasync:{re.escape(ctx.region)}:{ctx.account}:"
               r"location/loc-[0-9a-f]{17}")
    assert re.fullmatch(pattern, loc_arn), (
        f"Ref Loc {loc_arn!r} is not a DataSync location ARN in this account and region"
    )
    listed = _location_arns_for_uri(ds, uri)
    assert listed == [loc_arn], (
        f"expected ListLocations to hold exactly Ref Loc for {uri!r}, got {listed!r}"
    )


@tags("axis:happy-path", "cap:c3", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A CloudFormation AWS::DataSync::LocationObjectStorage's LocationUri reflects the
    template's hostname, bucket name and protocol; deleting the stack removes it, and
    DataSync then refuses to describe it.

    Reference: https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-datasync-locationobjectstorage.html
    """
    cfn = ctx.client("cloudformation")
    ds = ctx.client("datasync")

    stack = ctx.unique_name("sim2real-ds-objstore-")
    hostname = ctx.unique_name("sim2real-ds-objstore-host-") + ".example.invalid"
    bucket_name = ctx.unique_name("sim2real-ds-objstore-bucket-")

    stack_id = create_stack(ctx, cfn, stack, _template(hostname, bucket_name))

    status = wait_stack(cfn, stack_id)
    assert status == "CREATE_COMPLETE", f"stack {stack!r} ended {status!r}, expected CREATE_COMPLETE"

    outputs = stack_outputs(cfn, stack_id)
    loc_arn = outputs["LocArn"]

    want_uri = f"object-storage://{hostname}/{bucket_name}/"
    _assert_location_ref(ctx, ds, loc_arn, want_uri)
    loc = ds.describe_location_object_storage(LocationArn=loc_arn)
    assert loc["ServerProtocol"] == "HTTPS", (
        f"expected ServerProtocol 'HTTPS', DescribeLocationObjectStorage reports {loc['ServerProtocol']!r}"
    )
    assert loc["LocationUri"] == outputs["LocUri"], (
        f"expected Fn::GetAtt Loc.LocationUri to match DescribeLocationObjectStorage LocationUri "
        f"{loc['LocationUri']!r}, got {outputs['LocUri']!r}"
    )
    assert loc["LocationUri"] == want_uri, (
        f"expected LocationUri {want_uri!r} from the template's ServerHostname and BucketName, "
        f"got {loc['LocationUri']!r}"
    )

    delete_stack(cfn, stack_id)
    stack_gone = ("ValidationError", f"Stack with id {stack} does not exist")
    expect_error(lambda: cfn.describe_stacks(StackName=stack), *stack_gone)

    location_object_storage_gone = (
        "InvalidRequestException",
        f"Location {loc_arn} is not found.",
    )
    expect_error(
        lambda: ds.describe_location_object_storage(LocationArn=loc_arn),
        *location_object_storage_gone,
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
