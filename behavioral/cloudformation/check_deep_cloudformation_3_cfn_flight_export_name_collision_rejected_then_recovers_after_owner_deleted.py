"""deep-cloudformation-3-cfn-flight-export-name-collision-rejected-then-recovers-after-owner-deleted."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deep-cloudformation-3-cfn-flight-export-name-collision-rejected-then-recovers-after-owner-deleted"
GROUP = "exports"
SERVICES = ["cloudformation"]


def _template(export_name: str, value: str) -> str:
    return json.dumps({
        "Resources": {"Anchor": {"Type": "AWS::CloudFormation::WaitConditionHandle"}},
        "Outputs": {"Shared": {"Value": value, "Export": {"Name": export_name}}},
    })


@tags("cap:c3", "concern:negative-classes", "plane:control", "axis:rejection")
def run(ctx) -> None:
    """Export.Name is a region-wide single-owner namespace: a second stack exporting an owned name
    fails and rolls back naming the owner; once the owner is deleted, the same stack succeeds."""
    cf = ctx.client("cloudformation")
    export_name = ctx.unique_name("sim2real-behav-cfnflight-exp-")
    owner = ctx.unique_name("sim2real-behav-cfnflight-own-")
    rival = ctx.unique_name("sim2real-behav-cfnflight-riv-")
    rival_body = _template(export_name, "rival-value")

    owner_id = cf.create_stack(StackName=owner, TemplateBody=_template(export_name, "owner-value"),
                               Tags=[{"Key": "sim2real-check", "Value": "cfn-flight"}])["StackId"]
    ctx.on_cleanup(lambda: _delete_quiet(cf, owner_id))
    status = _wait_settled(cf, owner_id)
    assert status == "CREATE_COMPLETE", f"owner stack ended {status!r}, expected 'CREATE_COMPLETE'"
    exports = _exports(cf)
    assert exports.get(export_name) == (owner_id, "owner-value"), (
        f"export {export_name!r} is {exports.get(export_name)!r}, expected owned by {owner_id!r} with 'owner-value'"
    )

    # Negative: the rival is accepted (the collision is asynchronous), then fails and rolls back.
    rival_id = cf.create_stack(StackName=rival, TemplateBody=rival_body,
                               Tags=[{"Key": "sim2real-check", "Value": "cfn-flight"}])["StackId"]
    ctx.on_cleanup(lambda: _delete_quiet(cf, rival_id))
    status = _wait_settled(cf, rival_id)
    assert status == "ROLLBACK_COMPLETE", f"rival stack ended {status!r}, expected 'ROLLBACK_COMPLETE'"
    reasons = [e.get("ResourceStatusReason") for e in _events(cf, rival_id)
               if e["LogicalResourceId"] == rival and e["ResourceStatus"] == "ROLLBACK_IN_PROGRESS"]
    expected = (f"Export with name {export_name} is already exported by stack {owner}. "
                "Rollback requested by user.")
    assert reasons == [expected], f"rival rollback reason(s) were {reasons!r}, expected [{expected!r}]"
    # Effect absent: the export still belongs to the owner, with the owner's value.
    exports = _exports(cf)
    assert exports.get(export_name) == (owner_id, "owner-value"), (
        f"after the collision export {export_name!r} is {exports.get(export_name)!r}; it must stay with the owner"
    )

    # Clear the way: the failed rival (ROLLBACK_COMPLETE) and then the owner are deleted.
    cf.delete_stack(StackName=rival_id)
    status = _wait_settled(cf, rival_id)
    assert status == "DELETE_COMPLETE", f"rolled-back rival deleted to {status!r}, expected 'DELETE_COMPLETE'"
    cf.delete_stack(StackName=owner_id)
    status = _wait_settled(cf, owner_id)
    assert status == "DELETE_COMPLETE", f"owner deleted to {status!r}, expected 'DELETE_COMPLETE'"
    assert export_name not in _exports(cf), f"export {export_name!r} survived its owner's deletion"

    # Positive control: the identical rival request now succeeds and owns the export.
    retry_id = cf.create_stack(StackName=rival, TemplateBody=rival_body,
                               Tags=[{"Key": "sim2real-check", "Value": "cfn-flight"}])["StackId"]
    ctx.on_cleanup(lambda: _delete_quiet(cf, retry_id))
    assert retry_id != rival_id, f"the retried rival reused the deleted stack id {rival_id!r}"
    status = _wait_settled(cf, retry_id)
    assert status == "CREATE_COMPLETE", f"retried rival ended {status!r}, expected 'CREATE_COMPLETE'"
    exports = _exports(cf)
    assert exports.get(export_name) == (retry_id, "rival-value"), (
        f"export {export_name!r} is {exports.get(export_name)!r}, expected owned by {retry_id!r} with 'rival-value'"
    )



def _exports(cf) -> dict:
    """Name -> (ExportingStackId, Value), paginated: the export namespace is account-wide."""
    out = {}
    for page in cf.get_paginator("list_exports").paginate():
        for e in page.get("Exports", []):
            out[e["Name"]] = (e["ExportingStackId"], e["Value"])
    return out


def _events(cf, stack_id: str) -> list:
    out = []
    for page in cf.get_paginator("describe_stack_events").paginate(StackName=stack_id):
        out.extend(page["StackEvents"])
    return out


def _wait_settled(cf, stack_id: str, timeout_s: float = 600.0) -> str:
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        status = cf.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
        if not status.endswith("_IN_PROGRESS"):
            return status
        time.sleep(3)
    raise AssertionError(f"stack {stack_id} did not settle within {timeout_s}s (last={status!r})")


def _delete_quiet(cf, stack_id: str) -> None:
    try:
        cf.delete_stack(StackName=stack_id)
        _wait_settled(cf, stack_id)
    except ClientError as exc:
        raise RuntimeError(f"stack {stack_id}: {exc}") from exc


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
