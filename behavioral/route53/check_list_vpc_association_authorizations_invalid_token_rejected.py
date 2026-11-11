"""list-vpc-association-authorizations-invalid-token-rejected."""
from __future__ import annotations

import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-vpc-association-authorizations-invalid-token-rejected"
GROUP = "error-semantics"
SERVICES = ["route53"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ListVPCAssociationAuthorizations rejects a malformed/stale NextToken with
    InvalidPaginationToken instead of silently returning a page or an empty list."""
    route53 = ctx.client("route53")

    vpc1 = _create_vpc(ctx)
    vpc2 = _create_vpc(ctx)

    zone_id = route53.create_hosted_zone(
        Name=f"{ctx.unique_name('sim2real-behav-')}.example.com",
        CallerReference=str(uuid.uuid4()),
        VPC={"VPCRegion": ctx.region, "VPCId": vpc1},
    )["HostedZone"]["Id"]
    ctx.on_cleanup(lambda: route53.delete_hosted_zone(Id=zone_id))

    # Create a real pending authorization so a valid (tokenless) call has content.
    route53.create_vpc_association_authorization(
        HostedZoneId=zone_id, VPC={"VPCRegion": ctx.region, "VPCId": vpc2}
    )
    ctx.on_cleanup(
        lambda: route53.delete_vpc_association_authorization(
            HostedZoneId=zone_id, VPC={"VPCRegion": ctx.region, "VPCId": vpc2}
        )
    )

    # Positive control: an unpaginated call succeeds and lists the authorization.
    good = route53.list_vpc_association_authorizations(HostedZoneId=zone_id)
    assert any(v["VPCId"] == vpc2 for v in good["VPCs"]), (
        f"positive control did not surface {vpc2!r}: {good['VPCs']!r}"
    )

    # Now use a syntactically-plausible but bogus/stale token.
    code, message = _client_error(
        lambda: route53.list_vpc_association_authorizations(
            HostedZoneId=zone_id, NextToken="not-a-real-pagination-token-0123456789"
        )
    )
    assert code == "InvalidPaginationToken", f"expected InvalidPaginationToken, got {code!r}"
    expected_message = "Invalid pagination token: not-a-real-pagination-token-0123456789"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # The bad-token call must not have disturbed the real authorization: an
    # independent re-read (positive control, repeated) still surfaces it.
    after = route53.list_vpc_association_authorizations(HostedZoneId=zone_id)
    assert any(v["VPCId"] == vpc2 for v in after["VPCs"]), (
        f"the rejected call disturbed the authorization: {after['VPCs']!r}"
    )


def _client_error(fn) -> tuple[str, str]:
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises, because
    an emulator ACCEPTING input real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(
        f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}"
    )


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
