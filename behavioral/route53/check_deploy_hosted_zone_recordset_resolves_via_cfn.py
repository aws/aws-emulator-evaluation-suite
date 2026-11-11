"""deploy-hosted-zone-recordset-resolves-via-cfn."""
from __future__ import annotations

import time
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "deploy-hosted-zone-recordset-resolves-via-cfn"
GROUP = "server-side"
SERVICES = ["route53"]


_TEMPLATE = """
AWSTemplateFormatVersion: '2010-09-09'
Parameters:
  ZoneName:
    Type: String
  RecordName:
    Type: String
Resources:
  HostedZone:
    Type: AWS::Route53::HostedZone
    Properties:
      Name: !Ref ZoneName
  RecordSet:
    Type: AWS::Route53::RecordSet
    Properties:
      HostedZoneId: !Ref HostedZone
      Name: !Ref RecordName
      Type: A
      TTL: '60'
      ResourceRecords:
        - 203.0.113.42
Outputs:
  HostedZoneId:
    Value: !Ref HostedZone
  RecordSetId:
    Value: !Ref RecordSet
"""


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:deploy", "dp:api", "plane:data")
def run(ctx) -> None:
    """A CloudFormation-deployed hosted zone and A record resolve via TestDNSAnswer.

    Asserts the record answers NOERROR with its value, not merely that the stack completed.
    """
    zone_name = ctx.unique_name("sim2real-r53-cfn-") + ".example."
    record_name = "www." + zone_name

    stack = _deploy_cfn(
        ctx,
        _TEMPLATE,
        params={"ZoneName": zone_name, "RecordName": record_name},
    )
    zone_id = stack["outputs"]["HostedZoneId"]

    route53 = ctx.client("route53")
    hz = route53.get_hosted_zone(Id=zone_id)
    assert hz["HostedZone"]["Name"] == zone_name

    answer = _poll_test_dns_answer(ctx, zone_id, record_name, "A")
    assert answer["ResponseCode"] == "NOERROR"
    assert answer["RecordData"] == ["203.0.113.42"]


def _safe(fn) -> None:
    try:
        fn()
    except ClientError:
        pass


def _wait_for_stack_status(
    ctx,
    stack_name: str,
    ok_statuses: set[str],
    bad_statuses: set[str],
    timeout_s: float = 300.0,
    interval_s: float = 5.0,
) -> dict[str, Any]:
    cfn = ctx.client("cloudformation")
    deadline = time.monotonic() + timeout_s
    last_status = None
    while time.monotonic() < deadline:
        resp = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]
        last_status = resp["StackStatus"]
        if last_status in ok_statuses:
            return resp
        if last_status in bad_statuses:
            raise AssertionError(f"stack {stack_name} entered {last_status}")
        time.sleep(interval_s)
    raise AssertionError(f"stack {stack_name} never reached {ok_statuses}, last saw {last_status}")


def _delete_stack(ctx, stack_name: str, timeout_s: float = 300.0, interval_s: float = 5.0) -> None:
    cfn = ctx.client("cloudformation")
    _safe(lambda: cfn.delete_stack(StackName=stack_name))
    deadline = time.monotonic() + timeout_s
    last_status = None
    while time.monotonic() < deadline:
        try:
            resp = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]
        except ClientError:
            return
        last_status = resp["StackStatus"]
        if last_status == "DELETE_COMPLETE":
            return
        time.sleep(interval_s)
    raise AssertionError(f"stack {stack_name} never reached DELETE_COMPLETE, last saw {last_status}")


def _deploy_cfn(ctx, template_body: str, params: dict[str, str] | None = None) -> dict[str, Any]:
    cfn = ctx.client("cloudformation")
    stack_name = ctx.unique_name("sim2real-r53-cfn-")
    kwargs: dict[str, Any] = {
        "StackName": stack_name,
        "TemplateBody": template_body,
        "Tags": [{"Key": "sim2real-check", "Value": stack_name}],
    }
    if params:
        kwargs["Parameters"] = [{"ParameterKey": k, "ParameterValue": v} for k, v in params.items()]
    cfn.create_stack(**kwargs)
    ctx.on_cleanup(lambda: _delete_stack(ctx, stack_name))
    _wait_for_stack_status(
        ctx, stack_name, {"CREATE_COMPLETE"}, {"CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED"}
    )
    resp = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]
    outputs = {o["OutputKey"]: o["OutputValue"] for o in resp.get("Outputs", [])}
    return {"stack_name": stack_name, "outputs": outputs}


def _poll_test_dns_answer(
    ctx, zone_id: str, record_name: str, record_type: str, timeout_s: float = 60.0, interval_s: float = 3.0
) -> dict[str, Any]:
    route53 = ctx.client("route53")
    deadline = time.monotonic() + timeout_s
    last_exc: Exception | None = None
    while time.monotonic() < deadline:
        try:
            return route53.test_dns_answer(
                HostedZoneId=zone_id, RecordName=record_name, RecordType=record_type
            )
        except ClientError as exc:
            last_exc = exc
            time.sleep(interval_s)
    assert last_exc is not None
    raise last_exc


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
