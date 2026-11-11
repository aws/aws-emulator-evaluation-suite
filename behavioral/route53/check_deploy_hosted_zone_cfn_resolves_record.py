"""deploy-hosted-zone-cfn-resolves-record."""
from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags

CHECK = "deploy-hosted-zone-cfn-resolves-record"
GROUP = "deploy"
SERVICES = ["route53"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:deploy", "dp:api", "plane:data")
def run(ctx) -> None:
    """A public hosted zone and A record deployed by a CloudFormation stack reach CREATE_COMPLETE
    and TestDNSAnswer serves the record; the stack then deletes cleanly.
    """
    cfn = ctx.client("cloudformation")
    route53 = ctx.client("route53")

    zone_name = f"{ctx.unique_name('sim2real-cfn-zone')}.com.".replace("_", "-")
    record_name = f"www.{zone_name}"
    record_ip = "203.0.113.5"  # TEST-NET-3 (RFC 5737), safe non-routable literal
    stack_name = ctx.unique_name("sim2real-cfn-r53-stack")

    template = {
        "Resources": {
            "Zone": {
                "Type": "AWS::Route53::HostedZone",
                "Properties": {"Name": zone_name},
            },
            "Record": {
                "Type": "AWS::Route53::RecordSet",
                "Properties": {
                    "HostedZoneId": {"Ref": "Zone"},
                    "Name": record_name,
                    "Type": "A",
                    "TTL": "60",
                    "ResourceRecords": [record_ip],
                },
            },
        },
        "Outputs": {
            "ZoneId": {"Value": {"Ref": "Zone"}},
        },
    }

    cfn.create_stack(
        StackName=stack_name,
        TemplateBody=json.dumps(template),
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _delete_stack(ctx, stack_name))

    status = _poll_until(
        probe=lambda: cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"],
        predicate=lambda s: s in ("CREATE_COMPLETE", "ROLLBACK_COMPLETE", "CREATE_FAILED"),
        timeout_s=180,
        interval_s=5,
        timeout_msg=f"stack {stack_name} did not reach a terminal status within 180s",
    )
    assert status == "CREATE_COMPLETE", f"stack did not reach CREATE_COMPLETE: {status}"

    outputs = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["Outputs"]
    zone_id = next(o["OutputValue"] for o in outputs if o["OutputKey"] == "ZoneId")

    def _resolves() -> dict[str, Any] | None:
        resp = route53.test_dns_answer(
            HostedZoneId=zone_id, RecordName=record_name, RecordType="A"
        )
        if resp.get("ResponseCode") == "NOERROR" and record_ip in resp.get("RecordData", []):
            return resp
        return None

    answer = _poll_until(
        probe=_resolves,
        predicate=lambda r: r is not None,
        timeout_s=60,
        interval_s=3,
        timeout_msg="record never resolved via TestDNSAnswer within 60s",
    )
    assert answer["ResponseCode"] == "NOERROR", f"expected NOERROR, got {answer['ResponseCode']!r}"
    assert answer["RecordData"] == [record_ip], f"expected [{record_ip!r}], got {answer['RecordData']!r}"
    assert answer["RecordType"] == "A", f"expected record type A, got {answer['RecordType']!r}"

    # Teardown is asserted here (not left to the best-effort ctx.on_cleanup callback, whose
    # exceptions are swallowed so a failed delete can't mask the verdict above) so a
    # stack that refuses to delete is itself a failure of this check, not a silent leak.
    _delete_stack(ctx, stack_name)


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float, timeout_msg: str):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{timeout_msg} (last observed: {last!r})")


def _delete_stack(ctx, stack_name: str) -> None:
    cfn = ctx.client("cloudformation")
    cfn.delete_stack(StackName=stack_name)
    status = _poll_until(
        probe=lambda: _stack_status(cfn, stack_name),
        predicate=lambda s: s in ("DELETE_COMPLETE", "DELETE_FAILED", None),
        timeout_s=180,
        interval_s=5,
        timeout_msg=f"stack {stack_name} did not finish deleting within 180s",
    )
    assert status in ("DELETE_COMPLETE", None), f"stack {stack_name} failed to delete: {status}"


def _stack_status(cfn, stack_name: str):
    try:
        return cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"]
    except Exception:
        return None


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
