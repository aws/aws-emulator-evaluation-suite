"""op-contract-deleteTransitGatewayMeteringPolicyEntry."""
from __future__ import annotations

import time
from datetime import datetime, timezone

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-deleteTransitGatewayMeteringPolicyEntry"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeleteTransitGatewayMeteringPolicyEntry removes an entry from a policy; bogus policy id -> NotFound."""
    ec2 = ctx.client("ec2")
    name = ctx.unique_name("sim2real-behav-tgwmpe-")

    tgw_id = _create_tgw(ctx, ec2, name)

    try:
        created = ec2.create_transit_gateway_metering_policy(
            TransitGatewayId=tgw_id,
            TagSpecifications=[
                {"ResourceType": "transit-gateway-metering-policy", "Tags": [{"Key": "Name", "Value": name}]}
            ],
        )
    except ClientError as exc:
        raise AssertionError(f"transit gateway metering policies unavailable: {exc.response['Error']['Code']}") from exc

    policy_id = created["TransitGatewayMeteringPolicy"]["TransitGatewayMeteringPolicyId"]
    ctx.on_cleanup(
        lambda: _best_effort(
            lambda: ec2.delete_transit_gateway_metering_policy(TransitGatewayMeteringPolicyId=policy_id)
        )
    )
    _poll(
        lambda: _policy_state(ec2, policy_id),
        lambda s: s == "available",
        timeout_s=120.0,
    )

    # MeteredAccount is not an AWS account id despite the name -- it is the closed enum
    # TransitGatewayMeteringPayerType ("source-attachment-owner" | "destination-attachment-owner" |
    # "transit-gateway-owner") naming WHO pays, not a specific account. Passing this check's own
    # account id there is a malformed request (real AWS rejects it with InvalidParameterValue),
    # so it is never the right value to send.
    ec2.create_transit_gateway_metering_policy_entry(
        TransitGatewayMeteringPolicyId=policy_id,
        PolicyRuleNumber=1,
        MeteredAccount="transit-gateway-owner",
    )

    # The response's PolicyRuleNumber is modelled as String (locationName "policyRuleNumber"),
    # even though the request field is Integer -- compare against the string form.
    entries_before = ec2.get_transit_gateway_metering_policy_entries(
        TransitGatewayMeteringPolicyId=policy_id
    )["TransitGatewayMeteringPolicyEntries"]
    assert any(e.get("PolicyRuleNumber") == "1" for e in entries_before), entries_before

    ec2.delete_transit_gateway_metering_policy_entry(
        TransitGatewayMeteringPolicyId=policy_id, PolicyRuleNumber=1
    )

    entries_after = ec2.get_transit_gateway_metering_policy_entries(
        TransitGatewayMeteringPolicyId=policy_id
    )["TransitGatewayMeteringPolicyEntries"]
    assert not any(e.get("PolicyRuleNumber") == "1" for e in entries_after), entries_after

    bogus_policy_id = _bogus_id_like(policy_id)
    error = _error(
        lambda: ec2.delete_transit_gateway_metering_policy_entry(
            TransitGatewayMeteringPolicyId=bogus_policy_id, PolicyRuleNumber=1
        )
    )
    assert error["Code"] == "InvalidTransitGatewayMeteringPolicyId.NotFound", error
    assert error.get("Message") == f"Transit Gateway Metering Policy Id {bogus_policy_id} was deleted or does not exist.", error


def _bogus_id_like(real_id):
    prefix, _, suffix = real_id.rpartition("-")
    return f"{prefix}-{'f' * len(suffix)}"

def _poll(probe, predicate, timeout_s=180.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _error(fn):
    """Call fn() and return its botocore Error dict; a call that succeeds raises AssertionError."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _policy_state(ec2, policy_id, treat_notfound_as=None):
    try:
        resp = ec2.describe_transit_gateway_metering_policies(TransitGatewayMeteringPolicyIds=[policy_id])
        policies = resp["TransitGatewayMeteringPolicies"]
        if not policies:
            return treat_notfound_as
        return policies[0]["State"]
    except ClientError as exc:
        if treat_notfound_as and "NotFound" in exc.response["Error"]["Code"]:
            return treat_notfound_as
        raise


def _retry_on_tgw_limit(ec2, fn, timeout_s=1500.0, interval_s=15.0):
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return fn()
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "TransitGatewayLimitExceeded" or time.monotonic() >= deadline:
                raise
            _reclaim_stale_tgws(ec2)
            time.sleep(interval_s)


def _reclaim_stale_tgws(ec2, min_age_s=1200.0):
    """Free transit gateway quota held by stale gateways of this suite: delete only an "available"
    gateway carrying this suite's Name-tag prefix, no live attachment, and a CreationTime older than
    min_age_s (beyond any check's run budget), so a gateway an in-flight check just created, or uses
    only for route tables, multicast domains or policies, is never deleted."""
    try:
        tgws = ec2.describe_transit_gateways(Filters=[{"Name": "state", "Values": ["available"]}])[
            "TransitGateways"
        ]
    except ClientError:
        return
    now = datetime.now(timezone.utc)
    for tgw in tgws:
        name_tag = next((t["Value"] for t in tgw.get("Tags", []) if t["Key"] == "Name"), "")
        if not name_tag.startswith("sim2real-behav-"):
            continue
        created = tgw.get("CreationTime")
        if created is None or (now - created).total_seconds() < min_age_s:
            continue
        tgw_id = tgw["TransitGatewayId"]
        try:
            live = ec2.describe_transit_gateway_attachments(
                Filters=[
                    {"Name": "transit-gateway-id", "Values": [tgw_id]},
                    {
                        "Name": "state",
                        "Values": [
                            "available", "pending", "pendingAcceptance", "modifying",
                            "initiatingRequest", "rollingBack",
                        ],
                    },
                ]
            )["TransitGatewayAttachments"]
        except ClientError:
            continue
        if live:
            continue
        try:
            ec2.delete_transit_gateway(TransitGatewayId=tgw_id)
        except ClientError:
            pass


def _create_tgw(ctx, ec2, name):
    created = _retry_on_tgw_limit(
        ec2,
        lambda: ec2.create_transit_gateway(
            Description=name,
            TagSpecifications=[{"ResourceType": "transit-gateway", "Tags": [{"Key": "Name", "Value": name}]}],
        )
    )
    tgw_id = created["TransitGateway"]["TransitGatewayId"]
    ctx.on_cleanup(lambda: _best_effort(lambda: ec2.delete_transit_gateway(TransitGatewayId=tgw_id)))
    _poll(
        lambda: ec2.describe_transit_gateways(TransitGatewayIds=[tgw_id])["TransitGateways"][0]["State"],
        lambda s: s == "available",
        timeout_s=180.0,
    )
    return tgw_id


def _best_effort(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "InvalidTransitGatewayID.NotFound",
            "InvalidTransitGatewayMeteringPolicyId.NotFound",
        ):
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
