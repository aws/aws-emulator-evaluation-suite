"""cfn-route53-recordset-hostedzone-id-and-name-both-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-route53-recordset-hostedzone-id-and-name-both-rejected"
GROUP = "deploy"
SERVICES = ["cloudformation", "route53"]

_TERMINAL = {
    "CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED",
    "DELETE_COMPLETE", "DELETE_FAILED",
}
_VALIDATION_REASON = "#: #: 2 subschemas matched instead of one"
_VALIDATION_PATH = "/Resources/R/Properties"


def _teardown(undo, *not_found: str):
    """A cleanup running ``undo()`` where a failed delete raises."""

    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _template(*, include_zone_name: bool) -> str:
    props = {
        "HostedZoneId": {"Ref": "ZoneId"},
        "Name": {"Ref": "RecordName"},
        "Type": "A",
        "TTL": "60",
        "ResourceRecords": [{"Ref": "RecordValue"}],
    }
    if include_zone_name:
        props["HostedZoneName"] = {"Ref": "ZoneName"}
    return json.dumps({
        "Parameters": {
            "ZoneId": {"Type": "String"},
            "ZoneName": {"Type": "String"},
            "RecordName": {"Type": "String"},
            "RecordValue": {"Type": "String"},
        },
        "Resources": {"R": {"Type": "AWS::Route53::RecordSet", "Properties": props}},
    })


def _wait_terminal(cfn, name: str, timeout_s: float = 180.0) -> str:
    """Poll DescribeStacks until the stack reaches a terminal status; return it."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = cfn.describe_stacks(StackName=name)["Stacks"][0]["StackStatus"]
        if last in _TERMINAL:
            return last
        time.sleep(2)
    raise AssertionError(f"stack {name} did not reach a terminal state within {timeout_s}s (last={last!r})")


def _validation_errors(cfn, name: str) -> list[tuple]:
    """``(logical id, reason, path)`` of each VALIDATION_ERROR operation event for R."""
    out: list[tuple] = []
    kwargs = {"StackName": name}
    while True:
        page = cfn.describe_events(**kwargs)
        out.extend(
            (e.get("LogicalResourceId"), e.get("ValidationStatusReason"), e.get("ValidationPath"))
            for e in page["OperationEvents"]
            if e.get("EventType") == "VALIDATION_ERROR" and e.get("LogicalResourceId") == "R"
        )
        if not page.get("NextToken"):
            return out
        kwargs["NextToken"] = page["NextToken"]


def _delete_stack(cfn, name: str) -> None:
    cfn.delete_stack(StackName=name)
    cfn.get_waiter("stack_delete_complete").wait(
        StackName=name, WaiterConfig={"Delay": 2, "MaxAttempts": 150})


def _record_sets(route53, zone_id: str) -> list[dict]:
    out: list[dict] = []
    kwargs = {"HostedZoneId": zone_id}
    while True:
        page = route53.list_resource_record_sets(**kwargs)
        out.extend(page["ResourceRecordSets"])
        if not page.get("IsTruncated"):
            return out
        kwargs["StartRecordName"] = page["NextRecordName"]
        kwargs["StartRecordType"] = page["NextRecordType"]


def _record_names(route53, zone_id: str) -> set[str]:
    return {r["Name"] for r in _record_sets(route53, zone_id)}


@tags(
    "axis:rejection", "cap:c3", "concern:deploy", "concern:negative-classes", "plane:control",
)
def run(ctx) -> None:
    """A Route53 RecordSet declaring both HostedZoneId and HostedZoneName fails CloudFormation's
    oneOf pre-provisioning check with its exact message and creates no record, while declaring
    HostedZoneId alone deploys and the record reads back.
    """
    cfn = ctx.client("cloudformation")
    route53 = ctx.client("route53")

    zone_name = ctx.unique_name("sim2real-cfn-oneof-") + ".test."
    zone = route53.create_hosted_zone(
        Name=zone_name, CallerReference=ctx.unique_name("sim2real-cfn-oneof-ref-"),
    )["HostedZone"]
    zone_id = zone["Id"]
    ctx.on_cleanup(_teardown(lambda: route53.delete_hosted_zone(Id=zone_id), "NoSuchHostedZone"))

    good_record = "good." + zone_name
    bad_record = "bad." + zone_name

    # --- positive control: HostedZoneId alone deploys ---
    good_stack = ctx.unique_name("sim2real-cfn-oneof-ok-")
    cfn.create_stack(
        StackName=good_stack,
        TemplateBody=_template(include_zone_name=False),
        Parameters=[
            {"ParameterKey": "ZoneId", "ParameterValue": zone_id},
            {"ParameterKey": "ZoneName", "ParameterValue": zone_name},
            {"ParameterKey": "RecordName", "ParameterValue": good_record},
            {"ParameterKey": "RecordValue", "ParameterValue": "10.0.0.1"},
        ],
    )
    ctx.on_cleanup(lambda: _delete_stack(cfn, good_stack))
    status = _wait_terminal(cfn, good_stack)
    assert status == "CREATE_COMPLETE", f"control stack: expected CREATE_COMPLETE, got {status!r}"
    good_sets = [
        (r["Type"], r.get("TTL"), r.get("ResourceRecords"))
        for r in _record_sets(route53, zone_id) if r["Name"] == good_record
    ]
    assert good_sets == [("A", 60, [{"Value": "10.0.0.1"}])], (
        f"control record {good_record!r} read back from Route 53 as {good_sets!r}"
    )

    # --- negative: both HostedZoneId and HostedZoneName together ---
    bad_stack = ctx.unique_name("sim2real-cfn-oneof-bad-")
    cfn.create_stack(
        StackName=bad_stack,
        TemplateBody=_template(include_zone_name=True),
        Parameters=[
            {"ParameterKey": "ZoneId", "ParameterValue": zone_id},
            {"ParameterKey": "ZoneName", "ParameterValue": zone_name},
            {"ParameterKey": "RecordName", "ParameterValue": bad_record},
            {"ParameterKey": "RecordValue", "ParameterValue": "10.0.0.2"},
        ],
    )
    ctx.on_cleanup(lambda: _delete_stack(cfn, bad_stack))
    status = _wait_terminal(cfn, bad_stack)
    assert status == "ROLLBACK_COMPLETE", f"both members: expected ROLLBACK_COMPLETE, got {status!r}"
    found = _validation_errors(cfn, bad_stack)
    assert found == [("R", _VALIDATION_REASON, _VALIDATION_PATH)], (
        f"both members: validation errors expected a single ({_VALIDATION_REASON!r}, "
        f"{_VALIDATION_PATH!r}), got {found!r}"
    )
    resources = cfn.list_stack_resources(StackName=bad_stack)["StackResourceSummaries"]
    logical_ids = sorted(r["LogicalResourceId"] for r in resources)
    assert logical_ids == [], (
        f"both members: a stack rejected before provisioning must list no resources, got {logical_ids!r}"
    )
    names_after = _record_names(route53, zone_id)
    assert bad_record not in names_after, (
        f"both members: record {bad_record!r} must never have been created, found among {names_after!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
