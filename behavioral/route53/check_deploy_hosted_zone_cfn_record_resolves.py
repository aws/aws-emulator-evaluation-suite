"""deploy-hosted-zone-cfn-record-resolves."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-hosted-zone-cfn-record-resolves"
GROUP = "deploy"
SERVICES = ["route53"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:deploy", "dp:api", "plane:data")
def run(ctx) -> None:
    """A CloudFormation stack provisioning a HostedZone plus a RecordSet reaches
    CREATE_COMPLETE, and the record it creates is actually resolvable via
    TestDNSAnswer against Route 53's own authoritative name servers afterward."""
    cfn = ctx.client("cloudformation")
    route53 = ctx.client("route53")

    zone_name = f"{ctx.unique_name('sim2real-r53-')}.com."
    record_name = f"www.{zone_name}"
    stack_name = ctx.unique_name("sim2real-r53-stack-")

    template = {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Parameters": {
            "ZoneName": {"Type": "String"},
            "RecordName": {"Type": "String"},
        },
        "Resources": {
            "Zone": {
                "Type": "AWS::Route53::HostedZone",
                "Properties": {"Name": {"Ref": "ZoneName"}},
            },
            "RecordSet": {
                "Type": "AWS::Route53::RecordSet",
                "Properties": {
                    "HostedZoneId": {"Ref": "Zone"},
                    "Name": {"Ref": "RecordName"},
                    "Type": "A",
                    "TTL": "300",
                    "ResourceRecords": ["192.0.2.123"],
                },
            },
        },
        "Outputs": {"ZoneId": {"Value": {"Ref": "Zone"}}},
    }

    cfn.create_stack(
        StackName=stack_name,
        TemplateBody=json.dumps(template),
        Parameters=[
            {"ParameterKey": "ZoneName", "ParameterValue": zone_name},
            {"ParameterKey": "RecordName", "ParameterValue": record_name},
        ],
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _teardown_stack(ctx, stack_name))

    status = _wait_stack_status(
        ctx,
        stack_name,
        {"CREATE_COMPLETE", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED", "CREATE_FAILED"},
        timeout_s=300.0,
    )
    assert status == "CREATE_COMPLETE", f"stack ended in unexpected status {status!r}"

    outputs = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["Outputs"]
    zone_id = next(o["OutputValue"] for o in outputs if o["OutputKey"] == "ZoneId")

    answer = route53.test_dns_answer(
        HostedZoneId=zone_id, RecordName=record_name, RecordType="A"
    )
    assert answer["ResponseCode"] == "NOERROR", (
        f"expected NOERROR, got {answer['ResponseCode']!r}"
    )
    assert answer["RecordData"] == ["192.0.2.123"], (
        f"expected exactly ['192.0.2.123'], got {answer['RecordData']!r}"
    )

    # Teardown is asserted here as part of the claim: a stack that refuses to delete
    # is a failure of this check, not a silent leak.
    delete_status = _delete_stack(ctx, stack_name)
    assert delete_status == "DELETE_COMPLETE", (
        f"stack {stack_name} failed to delete: {delete_status!r}"
    )


def _wait_stack_status(ctx, stack_name, target_statuses, timeout_s=300.0, interval_s=10.0):
    cfn = ctx.client("cloudformation")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        resp = cfn.describe_stacks(StackName=stack_name)
        last = resp["Stacks"][0]["StackStatus"]
        if last in target_statuses:
            return last
        time.sleep(interval_s)
    raise AssertionError(f"stack {stack_name} did not reach {target_statuses}, last={last}")


def _delete_stack(ctx, stack_name) -> str:
    cfn = ctx.client("cloudformation")
    cfn.delete_stack(StackName=stack_name)
    deadline = time.monotonic() + 300.0
    while time.monotonic() < deadline:
        try:
            resp = cfn.describe_stacks(StackName=stack_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ValidationError" and "does not exist" in str(exc):
                return "DELETE_COMPLETE"
            raise
        status = resp["Stacks"][0]["StackStatus"]
        if status in ("DELETE_COMPLETE", "DELETE_FAILED"):
            return status
        time.sleep(2.0)
    raise AssertionError(f"stack {stack_name} did not finish deleting within 300s")


def _teardown_stack(ctx, stack_name) -> None:
    status = _delete_stack(ctx, stack_name)
    assert status == "DELETE_COMPLETE", f"stack {stack_name} teardown ended {status}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
