"""associate-vpc-conflicting-domain-rejected."""
from __future__ import annotations

import time
import uuid
from typing import Any, Callable

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "associate-vpc-conflicting-domain-rejected"
GROUP = "error-semantics"
SERVICES = ["route53"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """AssociateVPCWithHostedZone rejects binding a VPC to a second private zone
    that shares a domain name with a zone already associated to that VPC."""
    route53 = ctx.client("route53")

    vpc1 = _create_vpc(ctx)
    vpc2 = _create_vpc(ctx)
    domain = f"{ctx.unique_name('sim2real-behav-')}.example.com"

    zone_a = route53.create_hosted_zone(
        Name=domain,
        CallerReference=str(uuid.uuid4()),
        VPC={"VPCRegion": ctx.region, "VPCId": vpc1},
    )["HostedZone"]["Id"]
    ctx.on_cleanup(lambda: _safe(lambda: route53.delete_hosted_zone(Id=zone_a)))

    # Zone B shares the same domain name but is created against a *different*
    # VPC (vpc2), so there is no conflict yet at creation time.
    zone_b = route53.create_hosted_zone(
        Name=domain,
        CallerReference=str(uuid.uuid4()),
        VPC={"VPCRegion": ctx.region, "VPCId": vpc2},
    )["HostedZone"]["Id"]
    ctx.on_cleanup(lambda: route53.delete_hosted_zone(Id=zone_b))

    # Now try to also bind vpc1 to zone B -- vpc1 is already bound to zone A,
    # which has the exact same domain name, so this must be rejected.
    def _associate_vpc1_to_b() -> None:
        route53.associate_vpc_with_hosted_zone(
            HostedZoneId=zone_b, VPC={"VPCRegion": ctx.region, "VPCId": vpc1}
        )

    code, message = _error(_associate_vpc1_to_b)
    assert code == "ConflictingDomainExists", f"expected ConflictingDomainExists, got {code!r}"
    expected = (
        f"The VPC {vpc1} in region {ctx.region} has already been associated with the hosted "
        f"zone {_zone_id(zone_a)} with the same domain name."
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Effect absent: vpc1 must still resolve only to zone A, not zone B. Poll to
    # ride out any list eventual-consistency lag rather than asserting instantly.
    def vpc1_zone_ids() -> set[str]:
        summaries = route53.list_hosted_zones_by_vpc(VPCId=vpc1, VPCRegion=ctx.region)[
            "HostedZoneSummaries"
        ]
        return {_zone_id(s["HostedZoneId"]) for s in summaries}

    ids = _poll_until(
        vpc1_zone_ids,
        lambda s: _zone_id(zone_a) in s,
        timeout_s=30.0,
        interval_s=2.0,
        description="zone A visible in vpc1's zone list",
    )
    assert _zone_id(zone_a) in ids, "zone A should remain associated with vpc1"
    assert _zone_id(zone_b) not in ids, "zone B must not have become associated with vpc1"

    # Restore: remove the conflict by deleting zone A, then retry the *identical*
    # associate call. This is the beat that separates "rejects this specific
    # domain conflict" from "AssociateVPCWithHostedZone is broken or denied
    # outright for this account" -- once vpc1 is no longer bound to any zone
    # sharing zone B's domain, the same call must succeed.
    route53.delete_hosted_zone(Id=zone_a)
    _retry_while_conflicting(_associate_vpc1_to_b, timeout_s=30.0, interval_s=2.0)

    ids_after_restore = _poll_until(
        vpc1_zone_ids,
        lambda s: _zone_id(zone_b) in s,
        timeout_s=30.0,
        interval_s=2.0,
        description="zone B visible in vpc1's zone list after the conflict clears",
    )
    assert _zone_id(zone_b) in ids_after_restore, "vpc1 should now be associated with zone B"


def _safe(fn) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchHostedZone":
            raise


def _error(fn) -> tuple[str, str]:
    """Call fn(); return the botocore (Error.Code, Error.Message). An unexpected success raises."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded with {result!r}")


def _retry_while_conflicting(fn, *, timeout_s: float, interval_s: float) -> None:
    """Retry fn() while it still reports ConflictingDomainExists, to ride out any
    propagation lag between deleting the conflicting zone and the domain-conflict
    check clearing. Raises on any other error, or if the conflict never clears."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            fn()
            return
        except ClientError as err:
            code = err.response["Error"]["Code"]
            if code != "ConflictingDomainExists" or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)


def _zone_id(full_id: str) -> str:
    return full_id.rsplit("/", 1)[-1]


def _poll_until(
    probe: Callable[[], Any],
    predicate: Callable[[Any], bool],
    *,
    timeout_s: float,
    interval_s: float,
    description: str = "condition",
) -> Any:
    deadline = time.monotonic() + timeout_s
    value = probe()
    while not predicate(value):
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"timed out after {timeout_s}s waiting for {description}; last saw {value!r}"
            )
        time.sleep(interval_s)
        value = probe()
    return value


def _create_vpc(ctx) -> str:
    ec2 = ctx.client("ec2")
    name = ctx.unique_name("sim2real-behav-vpc-")
    vpc_id = ec2.create_vpc(
        CidrBlock="10.0.0.0/16",
        TagSpecifications=[
            {"ResourceType": "vpc", "Tags": [{"Key": "Name", "Value": name}]}
        ],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: ec2.delete_vpc(VpcId=vpc_id))
    ec2.get_waiter("vpc_available").wait(VpcIds=[vpc_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})
    return vpc_id


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
