"""op-contract-create-verified-access-endpoint."""
from __future__ import annotations

import time
from typing import Any, Callable, Optional

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "op-contract-create-verified-access-endpoint"
GROUP = "error-semantics"
SERVICES = ["ec2"]

_DRY_RUN_MESSAGE = "Request would have succeeded, but DryRun flag is set."


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateVerifiedAccessEndpoint: success creates a cidr-type endpoint wired to a real
    VPC/subnets/security group and bound to its Verified Access group; DryRun=True is
    honored (permission-checked, no mutation)."""
    ec2 = ctx.client("ec2")
    instance_id = _create_instance(ctx)
    _attach_trust_provider(ctx, instance_id)
    group_id = _create_group(ctx, instance_id)
    vpc_id, subnet_ids, sg_id = _create_network(ctx)

    # CidrOptions requires an explicit PortRanges list (real AWS rejects the request
    # with MissingParameter if it's omitted) and, for a "cidr" endpoint type, the only
    # supported IP protocol is "tcp" (not "https"/"http", which are only valid for
    # network-interface/load-balancer endpoint types). The request member is the
    # plural "PortRanges" -- not "PortRange" -- which botocore's own param validator
    # rejects as an unknown parameter.
    cidr_options = {
        "Cidr": "10.66.0.0/24",
        "Protocol": "tcp",
        "PortRanges": [{"FromPort": 443, "ToPort": 443}],
        "SubnetIds": subnet_ids,
    }
    endpoint_tag_spec = [
        {
            "ResourceType": "verified-access-endpoint",
            "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-behav-vae-")}],
        }
    ]

    # --- error boundary: DryRun must fail with DryRunOperation and create nothing ---
    code, message = _error(
        lambda: ec2.create_verified_access_endpoint(
            AttachmentType="vpc",
            EndpointType="cidr",
            VerifiedAccessGroupId=group_id,
            SecurityGroupIds=[sg_id],
            CidrOptions=cidr_options,
            DryRun=True,
        )
    )
    assert code == "DryRunOperation", f"unexpected code: {code}"
    assert message == _DRY_RUN_MESSAGE, f"unexpected DryRunOperation message {message!r}"
    before = ec2.describe_verified_access_endpoints(
        Filters=[{"Name": "verified-access-group-id", "Values": [group_id]}]
    )["VerifiedAccessEndpoints"]
    assert before == [], "DryRun must not create an endpoint"

    # --- success path ---
    resp = ec2.create_verified_access_endpoint(
        AttachmentType="vpc",
        EndpointType="cidr",
        VerifiedAccessGroupId=group_id,
        SecurityGroupIds=[sg_id],
        CidrOptions=cidr_options,
        TagSpecifications=endpoint_tag_spec,
    )
    ep = resp["VerifiedAccessEndpoint"]
    ep_id = ep["VerifiedAccessEndpointId"]
    ctx.on_cleanup(lambda: _delete_endpoint(ctx, ep_id))
    assert ep["VerifiedAccessGroupId"] == group_id, (
        f"expected group {group_id}, got {ep['VerifiedAccessGroupId']}"
    )
    assert ep["VerifiedAccessInstanceId"] == instance_id, (
        f"expected instance {instance_id}, got {ep['VerifiedAccessInstanceId']}"
    )
    assert ep["EndpointType"] == "cidr", f"expected cidr, got {ep['EndpointType']}"
    assert ep["AttachmentType"] == "vpc", f"expected vpc, got {ep['AttachmentType']}"
    assert ep["CidrOptions"]["Cidr"] == "10.66.0.0/24", (
        f"expected 10.66.0.0/24, got {ep['CidrOptions']['Cidr']}"
    )
    assert isinstance(ep["Status"]["Code"], str) and ep["Status"]["Code"], (
        f"expected a non-empty status code string, got {ep['Status']!r}"
    )

    # confirm the endpoint is observable via the read path too, and that the persisted
    # state (not just the mutating call's own echo) carries the same wiring
    listed = ec2.describe_verified_access_endpoints(VerifiedAccessEndpointIds=[ep_id])[
        "VerifiedAccessEndpoints"
    ]
    described = listed[0]
    assert described["VerifiedAccessEndpointId"] == ep_id, (
        f"expected {ep_id} in describe results, got {described['VerifiedAccessEndpointId']}"
    )
    assert described["VerifiedAccessGroupId"] == group_id, (
        f"expected persisted group {group_id}, got {described['VerifiedAccessGroupId']}"
    )
    assert described["EndpointType"] == "cidr", (
        f"expected persisted cidr, got {described['EndpointType']}"
    )
    assert described["AttachmentType"] == "vpc", (
        f"expected persisted vpc, got {described['AttachmentType']}"
    )
    assert described["CidrOptions"]["Cidr"] == "10.66.0.0/24", (
        f"expected persisted 10.66.0.0/24, got {described['CidrOptions']['Cidr']}"
    )


# ===== helpers =====

def _error(fn):
    """Call fn() and return the (code, message) of the ClientError it raises. A call that
    succeeds raises AssertionError: a target performing a call AWS refuses must not be
    reported as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _poll_until(probe: Callable[[], Any], predicate: Callable[[Any], bool], *, timeout_s: float = 120.0, interval_s: float = 3.0) -> Any:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _create_instance(ctx) -> str:
    ec2 = ctx.client("ec2")
    name = ctx.unique_name("sim2real-behav-vai-")
    instance_id = ec2.create_verified_access_instance(
        Description=name,
        TagSpecifications=[{"ResourceType": "verified-access-instance", "Tags": [{"Key": "Name", "Value": name}]}],
    )["VerifiedAccessInstance"]["VerifiedAccessInstanceId"]
    ctx.on_cleanup(lambda: _delete_instance(ctx, instance_id))
    return instance_id


def _create_group(ctx, instance_id: str) -> str:
    ec2 = ctx.client("ec2")
    name = ctx.unique_name("sim2real-behav-vag-")
    group_id = ec2.create_verified_access_group(
        VerifiedAccessInstanceId=instance_id,
        TagSpecifications=[{"ResourceType": "verified-access-group", "Tags": [{"Key": "Name", "Value": name}]}],
    )["VerifiedAccessGroup"]["VerifiedAccessGroupId"]
    ctx.on_cleanup(lambda: _delete_group(ctx, group_id))
    return group_id


def _attach_trust_provider(ctx, instance_id: str) -> str:
    # AWS requires a trust provider to be attached to a Verified Access instance
    # before any group can be created against it (even for a DryRun call). Also,
    # real AWS rejects CreateVerifiedAccessEndpoint for a "cidr"/TCP-based endpoint
    # unless the trust provider attached to its instance is configured for native
    # (non-browser) applications via NativeApplicationOidcOptions -- a plain OidcOptions
    # ("web") trust provider is rejected with InvalidParameterValue ("TCP based
    # endpoints require a TrustProvider with NativeApp").
    ec2 = ctx.client("ec2")
    policy_reference_name = ctx.unique_name("sim2realbehav").replace("-", "")[:32]
    native_application_oidc_options = {
        "PublicSigningKeyEndpoint": "https://issuer.example.com/keys",
        "Issuer": "https://issuer.example.com",
        "AuthorizationEndpoint": "https://issuer.example.com/authorize",
        "TokenEndpoint": "https://issuer.example.com/token",
        "UserInfoEndpoint": "https://issuer.example.com/userinfo",
        "ClientId": "sim2real-client-id",
        "ClientSecret": "sim2real-client-secret",
        "Scope": "openid",
    }
    tp_name = ctx.unique_name("sim2real-behav-vatp-")
    tp_id = ec2.create_verified_access_trust_provider(
        TrustProviderType="user",
        UserTrustProviderType="oidc",
        PolicyReferenceName=policy_reference_name,
        NativeApplicationOidcOptions=native_application_oidc_options,
        TagSpecifications=[
            {"ResourceType": "verified-access-trust-provider", "Tags": [{"Key": "Name", "Value": tp_name}]}
        ],
    )["VerifiedAccessTrustProvider"]["VerifiedAccessTrustProviderId"]
    ctx.on_cleanup(lambda: _detach_and_delete_trust_provider(ctx, instance_id, tp_id))
    ec2.attach_verified_access_trust_provider(
        VerifiedAccessInstanceId=instance_id, VerifiedAccessTrustProviderId=tp_id
    )
    return tp_id


def _detach_and_delete_trust_provider(ctx, instance_id: str, tp_id: str) -> None:
    ec2 = ctx.client("ec2")
    try:
        ec2.detach_verified_access_trust_provider(
            VerifiedAccessInstanceId=instance_id, VerifiedAccessTrustProviderId=tp_id
        )
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "InvalidVerifiedAccessInstanceId.NotFound":
            raise
    try:
        ec2.delete_verified_access_trust_provider(VerifiedAccessTrustProviderId=tp_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "InvalidVerifiedAccessTrustProviderId.NotFound":
            raise


def _create_network(ctx):
    from botocore.exceptions import ClientError

    ec2 = ctx.client("ec2")
    vpc_name = ctx.unique_name("sim2real-behav-vpc-")

    def _do_create():
        return ec2.create_vpc(
            CidrBlock="10.66.0.0/16",
            TagSpecifications=[{"ResourceType": "vpc", "Tags": [{"Key": "Name", "Value": vpc_name}]}],
        )

    # The account's small default VPC quota can be held by other checks running concurrently
    # against the same account and region; wait for them to release it in a bounded loop
    # instead of failing outright on VpcLimitExceeded.
    deadline = time.monotonic() + 300.0
    last_err: Optional[Exception] = None
    resp = None
    while time.monotonic() < deadline:
        try:
            resp = _do_create()
            break
        except ClientError as err:
            if err.response["Error"]["Code"] != "VpcLimitExceeded":
                raise
            last_err = err
            time.sleep(2)
    if resp is None:
        raise last_err
    vpc_id = resp["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _delete_vpc(ctx, vpc_id))
    ec2.get_waiter("vpc_available").wait(VpcIds=[vpc_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})

    azs = [
        z["ZoneName"]
        for z in ec2.describe_availability_zones(Filters=[{"Name": "state", "Values": ["available"]}])[
            "AvailabilityZones"
        ]
    ][:2]
    subnet_ids = []
    for i, az in enumerate(azs):
        subnet_name = ctx.unique_name("sim2real-behav-subnet-")
        sid = ec2.create_subnet(
            VpcId=vpc_id,
            CidrBlock=f"10.66.{i}.0/24",
            AvailabilityZone=az,
            TagSpecifications=[{"ResourceType": "subnet", "Tags": [{"Key": "Name", "Value": subnet_name}]}],
        )["Subnet"]["SubnetId"]
        ctx.on_cleanup(lambda sid=sid: _delete_subnet(ctx, sid))
        subnet_ids.append(sid)

    sg_name = ctx.unique_name("sim2real-behav-sg-")
    sg_id = ec2.create_security_group(
        GroupName=sg_name,
        Description=sg_name,
        VpcId=vpc_id,
        TagSpecifications=[{"ResourceType": "security-group", "Tags": [{"Key": "Name", "Value": sg_name}]}],
    )["GroupId"]
    ctx.on_cleanup(lambda: _delete_sg(ctx, sg_id))
    return vpc_id, subnet_ids, sg_id


def _delete_endpoint(ctx, ep_id: str) -> None:
    ec2 = ctx.client("ec2")
    try:
        ec2.delete_verified_access_endpoint(VerifiedAccessEndpointId=ep_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "InvalidVerifiedAccessEndpointId.NotFound":
            raise
        return
    try:
        _poll_until(
            lambda: ec2.describe_verified_access_endpoints(VerifiedAccessEndpointIds=[ep_id])[
                "VerifiedAccessEndpoints"
            ],
            lambda eps: eps == [],
            # An endpoint deleted while still provisioning stays `deleting` for minutes; the
            # bound leaves the suite's 900 s cleanup budget room for the network teardowns after it.
            timeout_s=720.0,
            interval_s=2.0,
        )
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "InvalidVerifiedAccessEndpointId.NotFound":
            raise


def _delete_group(ctx, group_id: str) -> None:
    ec2 = ctx.client("ec2")
    try:
        ec2.delete_verified_access_group(VerifiedAccessGroupId=group_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "InvalidVerifiedAccessGroupId.NotFound":
            raise


def _delete_instance(ctx, instance_id: str) -> None:
    ec2 = ctx.client("ec2")
    try:
        ec2.delete_verified_access_instance(VerifiedAccessInstanceId=instance_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "InvalidVerifiedAccessInstanceId.NotFound":
            raise


def _delete_sg(ctx, sg_id: str) -> None:
    ec2 = ctx.client("ec2")
    try:
        ec2.delete_security_group(GroupId=sg_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "InvalidGroup.NotFound":
            raise


def _delete_subnet(ctx, subnet_id: str) -> None:
    ec2 = ctx.client("ec2")
    try:
        ec2.delete_subnet(SubnetId=subnet_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "InvalidSubnetID.NotFound":
            raise


def _delete_vpc(ctx, vpc_id: str) -> None:
    ec2 = ctx.client("ec2")
    try:
        ec2.delete_vpc(VpcId=vpc_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "InvalidVpcID.NotFound":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
