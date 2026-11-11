"""op-contract-modify-verified-access-endpoint."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "op-contract-modify-verified-access-endpoint"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ModifyVerifiedAccessEndpoint updates the description, echoed and read back; an unknown endpoint
    id fails with InvalidVerifiedAccessEndpointId.NotFound."""
    ec2 = ctx.client("ec2")

    vpc_id, subnet_id, sg_id = _make_network(ctx, ec2)
    vai_id, group_id = _make_instance_and_group(ctx, ec2)

    endpoint = ec2.create_verified_access_endpoint(
        VerifiedAccessGroupId=group_id,
        EndpointType="cidr",
        AttachmentType="vpc",
        SecurityGroupIds=[sg_id],
        CidrOptions={
            "Cidr": "10.88.2.0/24",
            "PortRanges": [{"FromPort": 443, "ToPort": 443}],
            "Protocol": "tcp",
            "SubnetIds": [subnet_id],
        },
        Description="initial",
        TagSpecifications=[
            {"ResourceType": "verified-access-endpoint", "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-vae-")}]}
        ],
    )["VerifiedAccessEndpoint"]
    endpoint_id = endpoint["VerifiedAccessEndpointId"]
    ctx.on_cleanup(lambda: ec2.delete_verified_access_endpoint(VerifiedAccessEndpointId=endpoint_id))

    new_desc = ctx.unique_name("sim2real-vae-desc-")
    resp = ec2.modify_verified_access_endpoint(VerifiedAccessEndpointId=endpoint_id, Description=new_desc)
    assert resp["VerifiedAccessEndpoint"]["Description"] == new_desc, resp["VerifiedAccessEndpoint"]

    described = ec2.describe_verified_access_endpoints(VerifiedAccessEndpointIds=[endpoint_id])[
        "VerifiedAccessEndpoints"
    ][0]
    assert described["Description"] == new_desc, "modification did not persist"

    code = _error_code(
        lambda: ec2.modify_verified_access_endpoint(VerifiedAccessEndpointId="vae-00000000000000000", Description="x")
    )
    assert code == "InvalidVerifiedAccessEndpointId.NotFound", f"unexpected error code: {code}"


def _make_network(ctx, ec2):
    name = ctx.unique_name("sim2real-vae-")
    vpc_id = ec2.create_vpc(
        CidrBlock="10.88.0.0/16",
        TagSpecifications=[{"ResourceType": "vpc", "Tags": [{"Key": "Name", "Value": name}]}],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: ec2.delete_vpc(VpcId=vpc_id))
    az = ec2.describe_availability_zones()["AvailabilityZones"][0]["ZoneName"]
    subnet_id = ec2.create_subnet(
        VpcId=vpc_id,
        CidrBlock="10.88.1.0/24",
        AvailabilityZone=az,
        TagSpecifications=[{"ResourceType": "subnet", "Tags": [{"Key": "Name", "Value": name}]}],
    )["Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda: ec2.delete_subnet(SubnetId=subnet_id))
    sg_id = ec2.create_security_group(
        VpcId=vpc_id,
        GroupName=ctx.unique_name("sim2real-sg-"),
        Description="sim2real behavioral test sg",
        TagSpecifications=[{"ResourceType": "security-group", "Tags": [{"Key": "Name", "Value": name}]}],
    )["GroupId"]
    ctx.on_cleanup(lambda: ec2.delete_security_group(GroupId=sg_id))
    return vpc_id, subnet_id, sg_id


def _make_instance_and_group(ctx, ec2):
    name = ctx.unique_name("sim2real-vae-")
    vai_id = ec2.create_verified_access_instance(
        TagSpecifications=[{"ResourceType": "verified-access-instance", "Tags": [{"Key": "Name", "Value": name}]}],
    )["VerifiedAccessInstance"]["VerifiedAccessInstanceId"]
    ctx.on_cleanup(lambda: ec2.delete_verified_access_instance(VerifiedAccessInstanceId=vai_id))

    vatp_id = ec2.create_verified_access_trust_provider(
        TrustProviderType="user",
        UserTrustProviderType="oidc",
        PolicyReferenceName=ctx.unique_name("sim2real_vatp_").replace("-", "_"),
        TagSpecifications=[
            {"ResourceType": "verified-access-trust-provider", "Tags": [{"Key": "Name", "Value": name}]}
        ],
        OidcOptions={
            "Issuer": "https://sim2real-behavioral-test.example.com",
            "AuthorizationEndpoint": "https://sim2real-behavioral-test.example.com/authorize",
            "TokenEndpoint": "https://sim2real-behavioral-test.example.com/token",
            "UserInfoEndpoint": "https://sim2real-behavioral-test.example.com/userinfo",
            "ClientId": "sim2real-client-id",
            "ClientSecret": "sim2real-client-secret",
            "Scope": "openid",
        },
        # TCP-based Verified Access endpoints (used below for the "cidr"
        # endpoint type) require the attached trust provider to also carry
        # native-application OIDC options.
        NativeApplicationOidcOptions={
            "Issuer": "https://sim2real-behavioral-test.example.com",
            "AuthorizationEndpoint": "https://sim2real-behavioral-test.example.com/authorize",
            "TokenEndpoint": "https://sim2real-behavioral-test.example.com/token",
            "UserInfoEndpoint": "https://sim2real-behavioral-test.example.com/userinfo",
            "PublicSigningKeyEndpoint": "https://sim2real-behavioral-test.example.com/keys",
            "ClientId": "sim2real-client-id",
            "ClientSecret": "sim2real-client-secret",
            "Scope": "openid",
        },
    )["VerifiedAccessTrustProvider"]["VerifiedAccessTrustProviderId"]
    ctx.on_cleanup(lambda: ec2.delete_verified_access_trust_provider(VerifiedAccessTrustProviderId=vatp_id))
    ec2.attach_verified_access_trust_provider(
        VerifiedAccessInstanceId=vai_id, VerifiedAccessTrustProviderId=vatp_id
    )
    ctx.on_cleanup(
        lambda: ec2.detach_verified_access_trust_provider(
            VerifiedAccessInstanceId=vai_id, VerifiedAccessTrustProviderId=vatp_id
        )
    )

    group_id = ec2.create_verified_access_group(
        VerifiedAccessInstanceId=vai_id,
        TagSpecifications=[{"ResourceType": "verified-access-group", "Tags": [{"Key": "Name", "Value": name}]}],
    )["VerifiedAccessGroup"]["VerifiedAccessGroupId"]
    ctx.on_cleanup(lambda: ec2.delete_verified_access_group(VerifiedAccessGroupId=group_id))
    return vai_id, group_id


def _error_code(fn):
    """Call fn(); return its botocore error code. An unexpected SUCCESS raises, because an emulator
    ACCEPTING a call real AWS refuses is the strongest signal available."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"]
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
