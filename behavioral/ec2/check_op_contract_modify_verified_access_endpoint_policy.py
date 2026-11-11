"""op-contract-modify-verified-access-endpoint-policy."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "op-contract-modify-verified-access-endpoint-policy"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ModifyVerifiedAccessEndpointPolicy sets a Cedar policy on the endpoint; bad endpoint id -> NotFound."""
    ec2 = ctx.client("ec2")

    vpc_id, subnet_id, sg_id = _make_network(ctx, ec2)
    vai_id, group_id = _make_instance_and_group(ctx, ec2)

    endpoint_name = ctx.unique_name("sim2real-vae-")
    endpoint_id = ec2.create_verified_access_endpoint(
        VerifiedAccessGroupId=group_id,
        EndpointType="cidr",
        AttachmentType="vpc",
        SecurityGroupIds=[sg_id],
        CidrOptions={
            "Cidr": "10.89.2.0/24",
            "PortRanges": [{"FromPort": 443, "ToPort": 443}],
            "Protocol": "tcp",
            "SubnetIds": [subnet_id],
        },
        TagSpecifications=[
            {"ResourceType": "verified-access-endpoint", "Tags": [{"Key": "Name", "Value": endpoint_name}]}
        ],
    )["VerifiedAccessEndpoint"]["VerifiedAccessEndpointId"]
    ctx.on_cleanup(lambda: ec2.delete_verified_access_endpoint(VerifiedAccessEndpointId=endpoint_id))

    policy_doc = "permit(principal, action, resource);"
    resp = ec2.modify_verified_access_endpoint_policy(
        VerifiedAccessEndpointId=endpoint_id, PolicyEnabled=True, PolicyDocument=policy_doc
    )
    assert resp["PolicyEnabled"] is True, resp
    assert resp["PolicyDocument"].strip() == policy_doc, resp["PolicyDocument"]

    described = ec2.get_verified_access_endpoint_policy(VerifiedAccessEndpointId=endpoint_id)
    assert described["PolicyEnabled"] is True, described
    assert described["PolicyDocument"].strip() == policy_doc, (
        f"independent read did not reflect the set policy document: {described['PolicyDocument']!r}"
    )

    code, code_msg = _client_error(
        lambda: ec2.modify_verified_access_endpoint_policy(
            VerifiedAccessEndpointId="vae-00000000000000000", PolicyEnabled=True, PolicyDocument=policy_doc
        )
    )
    assert code == "InvalidVerifiedAccessEndpointId.NotFound", f"unexpected error code: {code}"
    assert code_msg == "The verified-access-endpoint ID 'vae-00000000000000000' does not exist", code_msg


def _make_network(ctx, ec2):
    vpc_name = ctx.unique_name("sim2real-vpc-")
    vpc_id = ec2.create_vpc(
        CidrBlock="10.89.0.0/16",
        TagSpecifications=[{"ResourceType": "vpc", "Tags": [{"Key": "Name", "Value": vpc_name}]}],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: ec2.delete_vpc(VpcId=vpc_id))
    az = ec2.describe_availability_zones()["AvailabilityZones"][0]["ZoneName"]
    subnet_name = ctx.unique_name("sim2real-subnet-")
    subnet_id = ec2.create_subnet(
        VpcId=vpc_id,
        CidrBlock="10.89.1.0/24",
        AvailabilityZone=az,
        TagSpecifications=[{"ResourceType": "subnet", "Tags": [{"Key": "Name", "Value": subnet_name}]}],
    )["Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda: ec2.delete_subnet(SubnetId=subnet_id))
    sg_name = ctx.unique_name("sim2real-sg-")
    sg_id = ec2.create_security_group(
        VpcId=vpc_id,
        GroupName=sg_name,
        Description="sim2real behavioral test sg",
        TagSpecifications=[{"ResourceType": "security-group", "Tags": [{"Key": "Name", "Value": sg_name}]}],
    )["GroupId"]
    ctx.on_cleanup(lambda: ec2.delete_security_group(GroupId=sg_id))
    return vpc_id, subnet_id, sg_id


def _make_instance_and_group(ctx, ec2):
    vai_name = ctx.unique_name("sim2real-vai-")
    vai_id = ec2.create_verified_access_instance(
        TagSpecifications=[
            {"ResourceType": "verified-access-instance", "Tags": [{"Key": "Name", "Value": vai_name}]}
        ]
    )["VerifiedAccessInstance"]["VerifiedAccessInstanceId"]
    ctx.on_cleanup(lambda: ec2.delete_verified_access_instance(VerifiedAccessInstanceId=vai_id))

    vatp_name = ctx.unique_name("sim2real-vatp-")
    vatp_id = ec2.create_verified_access_trust_provider(
        TrustProviderType="user",
        UserTrustProviderType="oidc",
        PolicyReferenceName=ctx.unique_name("sim2real_vatp_").replace("-", "_"),
        TagSpecifications=[
            {"ResourceType": "verified-access-trust-provider", "Tags": [{"Key": "Name", "Value": vatp_name}]}
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

    group_name = ctx.unique_name("sim2real-vag-")
    group_id = ec2.create_verified_access_group(
        VerifiedAccessInstanceId=vai_id,
        TagSpecifications=[
            {"ResourceType": "verified-access-group", "Tags": [{"Key": "Name", "Value": group_name}]}
        ],
    )["VerifiedAccessGroup"]["VerifiedAccessGroupId"]
    ctx.on_cleanup(lambda: ec2.delete_verified_access_group(VerifiedAccessGroupId=group_id))
    return vai_id, group_id


def _client_error(fn):
    """Call fn() and return its (code, message). An unexpected success raises, because an
    emulator accepting input real AWS refuses must not read as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
