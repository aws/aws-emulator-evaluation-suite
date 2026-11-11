"""op-contract-describeTransitGatewayMulticastDomains."""
from __future__ import annotations

import time
from datetime import datetime, timezone

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-describeTransitGatewayMulticastDomains"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeTransitGatewayMulticastDomains returns a created domain's transit gateway, owner and
    available state by ID, finds it by transit-gateway-id filter while an unknown gateway ID finds
    nothing, and DryRun answers DryRunOperation with its exact message."""
    ec2 = ctx.client("ec2")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    name = ctx.unique_name("sim2real-behav-tgwmc-")

    tgw_id = _create_tgw(ctx, ec2, name)

    created = ec2.create_transit_gateway_multicast_domain(
        TransitGatewayId=tgw_id,
        TagSpecifications=[
            {"ResourceType": "transit-gateway-multicast-domain", "Tags": [{"Key": "Name", "Value": name}]}
        ],
    )["TransitGatewayMulticastDomain"]
    domain_id = created["TransitGatewayMulticastDomainId"]
    ctx.on_cleanup(lambda: _delete_domain_and_wait(ec2, domain_id))

    state = _poll(
        lambda: _domain_state(ec2, domain_id),
        lambda s: s == "available",
        timeout_s=300.0,
    )
    assert state == "available", f"multicast domain never became available (last={state})"

    resp = ec2.describe_transit_gateway_multicast_domains(TransitGatewayMulticastDomainIds=[domain_id])
    domains = resp["TransitGatewayMulticastDomains"]
    assert len(domains) == 1, f"expected exactly 1 domain for its own id, got {len(domains)}"
    domain = domains[0]
    assert domain["TransitGatewayId"] == tgw_id, (
        f"expected TransitGatewayId {tgw_id}, got {domain['TransitGatewayId']}"
    )
    assert domain["OwnerId"] == account_id, f"expected OwnerId {account_id}, got {domain['OwnerId']}"
    assert domain["State"] == "available", f"expected State available, got {domain['State']}"

    resp_by_tgw = ec2.describe_transit_gateway_multicast_domains(
        Filters=[{"Name": "transit-gateway-id", "Values": [tgw_id]}]
    )
    found_ids = [d["TransitGatewayMulticastDomainId"] for d in resp_by_tgw["TransitGatewayMulticastDomains"]]
    assert domain_id in found_ids, f"expected {domain_id} in transit-gateway-id filtered result, got {found_ids}"

    # a Filters-based lookup on a bogus (but well-formed) transit-gateway-id must
    # deterministically return an empty collection rather than error, since Filters
    # never validate referenced IDs for existence
    resp_bogus = ec2.describe_transit_gateway_multicast_domains(
        Filters=[{"Name": "transit-gateway-id", "Values": ["tgw-00000000000000000"]}]
    )
    bogus_items = resp_bogus["TransitGatewayMulticastDomains"]
    assert bogus_items == [], f"expected empty filtered result for a bogus transit-gateway-id, got {bogus_items}"

    code, code_message = _error_code(lambda: ec2.describe_transit_gateway_multicast_domains(DryRun=True))
    assert code == "DryRunOperation", f"expected DryRunOperation, got {code!r}"
    expected_code_message = "Request would have succeeded, but DryRun flag is set."
    assert code_message == expected_code_message, f"expected message {expected_code_message!r}, got {code_message!r}"


def _poll(probe, predicate, timeout_s=180.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _error_code(fn):
    """Call fn() and return its (code, message); a call that succeeds raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _domain_state(ec2, domain_id):
    try:
        resp = ec2.describe_transit_gateway_multicast_domains(TransitGatewayMulticastDomainIds=[domain_id])
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "InvalidTransitGatewayMulticastDomainId.NotFound":
            return None
        raise
    domains = resp["TransitGatewayMulticastDomains"]
    if not domains:
        return None
    return domains[0]["State"]


def _create_tgw(ctx, ec2, name):
    created = _retry_on_tgw_limit(
        ec2,
        lambda: ec2.create_transit_gateway(
            Description=name,
            Options={"MulticastSupport": "enable"},
            TagSpecifications=[{"ResourceType": "transit-gateway", "Tags": [{"Key": "Name", "Value": name}]}],
        ),
    )
    tgw_id = created["TransitGateway"]["TransitGatewayId"]
    ctx.on_cleanup(lambda: _delete_tgw(ec2, tgw_id))
    _poll(
        lambda: ec2.describe_transit_gateways(TransitGatewayIds=[tgw_id])["TransitGateways"][0]["State"],
        lambda s: s == "available",
        timeout_s=420.0,
    )
    return tgw_id


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


def _retry_on_tgw_limit(ec2, fn, timeout_s=600.0, interval_s=20.0):
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return fn()
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "TransitGatewayLimitExceeded" or time.monotonic() >= deadline:
                raise
            _reclaim_stale_tgws(ec2)
            time.sleep(interval_s)


def _delete_domain_and_wait(ec2, domain_id):
    """Delete the multicast domain and wait until it is gone: its transit gateway refuses
    deletion while the domain still exists, even in the deleting state."""
    try:
        ec2.delete_transit_gateway_multicast_domain(TransitGatewayMulticastDomainId=domain_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "InvalidTransitGatewayMulticastDomainId.NotFound":
            raise
    _poll(lambda: _domain_state(ec2, domain_id), lambda s: s in (None, "deleted"), timeout_s=300.0)


def _delete_tgw(ec2, tgw_id):
    """Delete the transit gateway once its multicast domain is gone; a not-found counts as gone."""
    try:
        ec2.delete_transit_gateway(TransitGatewayId=tgw_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "InvalidTransitGatewayID.NotFound":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
