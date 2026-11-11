"""deploy-mailmanager-addresslist-archive-relay-round-trip-and-delete."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-mailmanager-addresslist-archive-relay-round-trip-and-delete"
GROUP = "deploy"
SERVICES = ["cloudformation", "mailmanager"]

# ---- CloudFormation helpers: copy VERBATIM; delete the ones the check never calls. ----

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

_TEMPLATE_BODY = """
AWSTemplateFormatVersion: '2010-09-09'
Parameters:
  AddressListNameParam:
    Type: String
  ArchiveNameParam:
    Type: String
  RelayNameParam:
    Type: String
Resources:
  AddressList:
    Type: AWS::SES::MailManagerAddressList
    Properties:
      AddressListName: !Ref AddressListNameParam
  Archive:
    Type: AWS::SES::MailManagerArchive
    Properties:
      ArchiveName: !Ref ArchiveNameParam
      Retention:
        RetentionPeriod: THREE_MONTHS
  Relay:
    Type: AWS::SES::MailManagerRelay
    Properties:
      RelayName: !Ref RelayNameParam
      ServerName: relay.sim2real.example.com
      ServerPort: 25
      Authentication:
        NoAuthentication: {}
Outputs:
  AddressListIdOut:
    Value: !Ref AddressList
  AddressListArnOut:
    Value: !GetAtt AddressList.AddressListArn
  ArchiveIdOut:
    Value: !Ref Archive
  ArchiveArnOut:
    Value: !GetAtt Archive.ArchiveArn
  ArchiveStateOut:
    Value: !GetAtt Archive.ArchiveState
  RelayIdOut:
    Value: !Ref Relay
  RelayArnOut:
    Value: !GetAtt Relay.RelayArn
"""


def _listed(mm, op: str, key: str, name_field: str, name: str) -> list[dict]:
    """Every entry a paginated MailManager List call returns under ``name``."""
    return [item for item in paginate(mm, op, key) if item[name_field] == name]


def _user_tags(mm, arn: str) -> dict:
    tag_list = mm.list_tags_for_resource(ResourceArn=arn)["Tags"]
    return {t["Key"]: t["Value"] for t in tag_list if not t["Key"].startswith("aws:")}


@tags("axis:happy-path", "cap:c3", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A CloudFormation MailManagerAddressList, Archive and Relay read back from MailManager with the
    template's properties and tags; after the delete each is gone, the archive PENDING_DELETION.

    Reference: https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-ses-mailmanagerarchive.html
    """
    cfn = ctx.client("cloudformation")
    mm = ctx.client("mailmanager")

    stack_name = ctx.unique_name("sim2real-cfn-mm-")
    al_name = ctx.unique_name("sim2real-cfn-mm-al-")
    archive_name = ctx.unique_name("sim2real-cfn-mm-arc-")
    relay_name = ctx.unique_name("sim2real-cfn-mm-rl-")

    stack_id = create_stack(
        ctx, cfn, stack_name, _TEMPLATE_BODY,
        Parameters=[
            {"ParameterKey": "AddressListNameParam", "ParameterValue": al_name},
            {"ParameterKey": "ArchiveNameParam", "ParameterValue": archive_name},
            {"ParameterKey": "RelayNameParam", "ParameterValue": relay_name},
        ],
    )
    status = wait_stack(cfn, stack_id)
    assert status == "CREATE_COMPLETE", (
        f"stack create ended in {status!r}: {decisive_rows(stack_events(cfn, stack_id))!r}"
    )
    outputs = stack_outputs(cfn, stack_id)

    al_id = outputs["AddressListIdOut"]
    archive_id = outputs["ArchiveIdOut"]
    relay_id = outputs["RelayIdOut"]

    listed = [e["AddressListId"] for e in _listed(mm, "list_address_lists", "AddressLists", "AddressListName", al_name)]
    assert listed == [al_id], f"ListAddressLists ids under {al_name!r} were {listed!r}, expected [Ref {al_id!r}]"
    listed = [e["ArchiveId"] for e in _listed(mm, "list_archives", "Archives", "ArchiveName", archive_name)]
    assert listed == [archive_id], (
        f"ListArchives ids under {archive_name!r} were {listed!r}, expected [Ref {archive_id!r}]"
    )
    listed = [e["RelayId"] for e in _listed(mm, "list_relays", "Relays", "RelayName", relay_name)]
    assert listed == [relay_id], f"ListRelays ids under {relay_name!r} were {listed!r}, expected [Ref {relay_id!r}]"

    al = mm.get_address_list(AddressListId=al_id)
    assert al["AddressListName"] == al_name, f"expected name {al_name!r}, got {al['AddressListName']!r}"
    assert al["AddressListArn"] == outputs["AddressListArnOut"], (
        f"GetAddressList arn {al['AddressListArn']!r} != stack GetAtt {outputs['AddressListArnOut']!r}"
    )

    archive = mm.get_archive(ArchiveId=archive_id)
    assert archive["ArchiveName"] == archive_name, (
        f"expected name {archive_name!r}, got {archive['ArchiveName']!r}"
    )
    assert archive["Retention"] == {"RetentionPeriod": "THREE_MONTHS"}, (
        f"expected Retention THREE_MONTHS, got {archive['Retention']!r}"
    )
    assert archive["ArchiveArn"] == outputs["ArchiveArnOut"], (
        f"GetArchive arn {archive['ArchiveArn']!r} != stack GetAtt {outputs['ArchiveArnOut']!r}"
    )
    assert archive["ArchiveState"] == outputs["ArchiveStateOut"] == "ACTIVE", (
        f"expected ArchiveState ACTIVE, got GetArchive={archive['ArchiveState']!r} "
        f"GetAtt={outputs['ArchiveStateOut']!r}"
    )

    relay = mm.get_relay(RelayId=relay_id)
    assert relay["RelayName"] == relay_name, f"expected name {relay_name!r}, got {relay['RelayName']!r}"
    assert relay["ServerName"] == "relay.sim2real.example.com", (
        f"expected ServerName relay.sim2real.example.com, got {relay['ServerName']!r}"
    )
    assert relay["ServerPort"] == 25, f"expected ServerPort 25, got {relay['ServerPort']!r}"
    assert relay["Authentication"] == {"NoAuthentication": {}}, (
        f"expected NoAuthentication, got {relay['Authentication']!r}"
    )
    assert relay["RelayArn"] == outputs["RelayArnOut"], (
        f"GetRelay arn {relay['RelayArn']!r} != stack GetAtt {outputs['RelayArnOut']!r}"
    )

    for label, arn in (
        ("address list", al["AddressListArn"]), ("archive", archive["ArchiveArn"]), ("relay", relay["RelayArn"])
    ):
        found = _user_tags(mm, arn)
        assert found == {"sim2real": stack_name}, (
            f"the {label}'s tags (aws: keys dropped) were {found!r}, expected the stack's propagated tag"
        )

    delete_stack(cfn, stack_id)

    al_gone = ("ResourceNotFoundException", f"Could not find AddressList with id {al_id}")
    expect_error(lambda: mm.get_address_list(AddressListId=al_id), *al_gone)
    relay_gone = ("ResourceNotFoundException", f"Relay does not exist: {relay_id}")
    expect_error(lambda: mm.get_relay(RelayId=relay_id), *relay_gone)

    archive_after = mm.get_archive(ArchiveId=archive_id)
    assert archive_after["ArchiveState"] == "PENDING_DELETION", (
        f"expected the deleted archive to read back PENDING_DELETION, got {archive_after['ArchiveState']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
