"""update-hosted-zone-features-value-round-trip."""
from __future__ import annotations

import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-hosted-zone-features-value-round-trip"
GROUP = "representation"
SERVICES = ["route53"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateHostedZoneFeatures enabling accelerated recovery on a private zone is rejected with
    InvalidInput and its exact message, and GetHostedZone's Features value is identical across
    reads before and after the refusal."""
    route53 = ctx.client("route53")
    ec2 = ctx.client("ec2")

    vpc_id = _create_vpc(ctx, ec2)

    zone_name = f"{ctx.unique_name('sim2real-hzfeatrt-')}.test"
    created = route53.create_hosted_zone(
        Name=zone_name,
        CallerReference=str(uuid.uuid4()),
        HostedZoneConfig={"PrivateZone": True},
        VPC={"VPCId": vpc_id, "VPCRegion": ctx.region},
    )
    zone_id = created["HostedZone"]["Id"]
    ctx.on_cleanup(lambda: route53.delete_hosted_zone(Id=zone_id))
    _wait_for_change_insync(route53, created["ChangeInfo"]["Id"])

    baseline_1 = route53.get_hosted_zone(Id=zone_id)["HostedZone"].get("Features")
    baseline_2 = route53.get_hosted_zone(Id=zone_id)["HostedZone"].get("Features")
    assert baseline_1 == baseline_2, (
        f"untouched Features representation is not stable across reads: {baseline_1!r} vs {baseline_2!r}"
    )

    # A private zone is used deliberately: enabling accelerated recovery on a public zone
    # succeeds and leaves the zone undeletable for hours.
    code, message = _error(
        lambda: route53.update_hosted_zone_features(HostedZoneId=zone_id, EnableAcceleratedRecovery=True)
    )
    assert code == "InvalidInput", (
        f"expected InvalidInput rejecting EnableAcceleratedRecovery=True on a private "
        f"zone (accelerated recovery is public-zone-only), got {code!r}"
    )
    expected = "Private hosted zones cannot enable accelerated recovery"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Rejected mutation: the value must round-trip as untouched, both immediately
    # after the rejection and on a subsequent independent read.
    after_1 = route53.get_hosted_zone(Id=zone_id)["HostedZone"].get("Features")
    after_2 = route53.get_hosted_zone(Id=zone_id)["HostedZone"].get("Features")
    assert after_1 == baseline_1 == after_2, (
        f"a rejected ({code}) UpdateHostedZoneFeatures call must not change the stored "
        f"value: baseline={baseline_1!r}, after={after_1!r}/{after_2!r}"
    )


def _error(fn):
    """Call fn(); return the botocore (Error.Code, Error.Message). A successful call raises."""
    try:
        result = fn()
    except ClientError as err:
        error = err.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")


def _create_vpc(ctx, ec2):
    """A VPC this check owns, with the DNS attributes a private hosted zone requires."""
    vpc_id = ec2.create_vpc(
        CidrBlock="10.0.0.0/16",
        TagSpecifications=[
            {"ResourceType": "vpc", "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-hzfeatrt-vpc-")}]}
        ],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: ec2.delete_vpc(VpcId=vpc_id))
    ec2.get_waiter("vpc_available").wait(VpcIds=[vpc_id], WaiterConfig={"Delay": 2, "MaxAttempts": 30})
    ec2.modify_vpc_attribute(VpcId=vpc_id, EnableDnsSupport={"Value": True})
    ec2.modify_vpc_attribute(VpcId=vpc_id, EnableDnsHostnames={"Value": True})
    return vpc_id


def _wait_for_change_insync(route53, change_id, timeout_s=120.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        status = route53.get_change(Id=change_id)["ChangeInfo"]["Status"]
        if status == "INSYNC":
            return
        time.sleep(interval_s)
    raise AssertionError(f"change {change_id} never reached INSYNC within {timeout_s}s")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

