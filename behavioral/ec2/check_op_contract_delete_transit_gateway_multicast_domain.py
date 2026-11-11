"""op-contract-deleteTransitGatewayMulticastDomain."""
from __future__ import annotations

import time
from datetime import datetime, timezone

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-deleteTransitGatewayMulticastDomain"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeleteTransitGatewayMulticastDomain tears down an available domain; re-deleting the same
    (now-gone) domain and deleting a never-created bogus id both -> NotFound."""
    ec2 = ctx.client("ec2")
    name = ctx.unique_name("sim2real-behav-tgwmc-")

    tgw_id = _create_tgw(ctx, ec2, name)

    created = ec2.create_transit_gateway_multicast_domain(
        TransitGatewayId=tgw_id,
        TagSpecifications=[
            {"ResourceType": "transit-gateway-multicast-domain", "Tags": [{"Key": "Name", "Value": name}]}
        ],
    )
    domain_id = created["TransitGatewayMulticastDomain"]["TransitGatewayMulticastDomainId"]
    ctx.on_cleanup(
        lambda: _best_effort(
            lambda: ec2.delete_transit_gateway_multicast_domain(TransitGatewayMulticastDomainId=domain_id)
        )
    )

    state = _poll(
        lambda: _domain_state(ec2, domain_id),
        lambda s: s == "available",
        timeout_s=120.0,
    )
    assert state == "available", f"multicast domain never became available (last={state})"

    delete_resp = ec2.delete_transit_gateway_multicast_domain(TransitGatewayMulticastDomainId=domain_id)
    delete_state = delete_resp["TransitGatewayMulticastDomain"]["State"]
    assert delete_state in ("deleting", "deleted"), f"unexpected state after delete: {delete_state!r}"

    final_state = _poll(
        lambda: _domain_state(ec2, domain_id, treat_notfound_as="deleted"),
        lambda s: s == "deleted",
        timeout_s=120.0,
    )
    assert final_state == "deleted", f"multicast domain never reached deleted (last={final_state})"

    redelete = _error(
        lambda: ec2.delete_transit_gateway_multicast_domain(TransitGatewayMulticastDomainId=domain_id)
    )
    assert redelete["Code"] == "InvalidTransitGatewayMulticastDomainId.NotFound", redelete
    assert redelete.get("Message") == f"Transit Gateway Multicast Domain {domain_id} was deleted or does not exist.", redelete

    bogus_domain_id = "tgw-mcast-domain-0123456789abcdef0"
    error = _error(
        lambda: ec2.delete_transit_gateway_multicast_domain(TransitGatewayMulticastDomainId=bogus_domain_id)
    )
    assert error["Code"] == "InvalidTransitGatewayMulticastDomainId.NotFound", error
    assert error.get("Message") == f"Transit Gateway Multicast Domain {bogus_domain_id} was deleted or does not exist.", error


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


def _domain_state(ec2, domain_id, treat_notfound_as=None):
    try:
        resp = ec2.describe_transit_gateway_multicast_domains(TransitGatewayMulticastDomainIds=[domain_id])
        domains = resp["TransitGatewayMulticastDomains"]
        if not domains:
            return treat_notfound_as
        return domains[0]["State"]
    except ClientError as exc:
        if treat_notfound_as and "NotFound" in exc.response["Error"]["Code"]:
            return treat_notfound_as
        raise


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
    ctx.on_cleanup(lambda: _best_effort(lambda: ec2.delete_transit_gateway(TransitGatewayId=tgw_id)))
    _poll(
        lambda: ec2.describe_transit_gateways(TransitGatewayIds=[tgw_id])["TransitGateways"][0]["State"],
        lambda s: s == "available",
        timeout_s=180.0,
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


def _best_effort(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "InvalidTransitGatewayID.NotFound",
            "InvalidTransitGatewayMulticastDomainId.NotFound",
        ):
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
