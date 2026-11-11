"""op-contract-get-verified-access-endpoint-policy."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-get-verified-access-endpoint-policy"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetVerifiedAccessEndpointPolicy: default-disabled policy for a fresh cidr endpoint, NotFound for a bogus id."""
    ec2 = ctx.client("ec2")

    # The endpoint created below is EndpointType="cidr" (a TCP-based endpoint).
    # AWS rejects TCP-based endpoints unless the attached trust provider is a
    # "native application" OIDC trust provider (NativeApplicationOidcOptions),
    # not a regular browser-based OidcOptions trust provider: "TCP based
    # endpoints require a TrustProvider with NativeApp".
    trust_provider_name = ctx.unique_name("sim2real-va-trust-provider-")
    trust_provider_id = ec2.create_verified_access_trust_provider(
        TrustProviderType="user",
        UserTrustProviderType="oidc",
        PolicyReferenceName="sim2realidp",
        NativeApplicationOidcOptions={
            "Issuer": "https://sim2real.example.com/oidc",
            "AuthorizationEndpoint": "https://sim2real.example.com/oidc/authorize",
            "TokenEndpoint": "https://sim2real.example.com/oidc/token",
            "UserInfoEndpoint": "https://sim2real.example.com/oidc/userinfo",
            "PublicSigningKeyEndpoint": "https://sim2real.example.com/oidc/jwks",
            "ClientId": "sim2real-client-id",
            "ClientSecret": "sim2real-client-secret",
            "Scope": "openid",
        },
        TagSpecifications=[
            {
                "ResourceType": "verified-access-trust-provider",
                "Tags": [{"Key": "Name", "Value": trust_provider_name}],
            }
        ],
    )["VerifiedAccessTrustProvider"]["VerifiedAccessTrustProviderId"]
    ctx.on_cleanup(
        lambda: ec2.delete_verified_access_trust_provider(VerifiedAccessTrustProviderId=trust_provider_id)
    )

    instance_id = _get_or_create_verified_access_instance(ec2, ctx)

    _attach_or_reuse_trust_provider(ec2, ctx, instance_id, trust_provider_id)

    group_name = ctx.unique_name("sim2real-va-group-")
    group_id = ec2.create_verified_access_group(
        VerifiedAccessInstanceId=instance_id,
        TagSpecifications=[
            {"ResourceType": "verified-access-group", "Tags": [{"Key": "Name", "Value": group_name}]}
        ],
    )["VerifiedAccessGroup"]["VerifiedAccessGroupId"]
    ctx.on_cleanup(lambda: ec2.delete_verified_access_group(VerifiedAccessGroupId=group_id))

    vpc_id, subnet_id, subnet_cidr = _existing_vpc_and_subnet(ec2, ctx=ctx)
    if vpc_id is None:
        vpc_name = ctx.unique_name("sim2real-va-vpc-")
        vpc_id = ec2.create_vpc(
            CidrBlock="10.91.0.0/16",
            TagSpecifications=[{"ResourceType": "vpc", "Tags": [{"Key": "Name", "Value": vpc_name}]}],
        )["Vpc"]["VpcId"]
        ctx.on_cleanup(lambda: ec2.delete_vpc(VpcId=vpc_id))
        subnet_name = ctx.unique_name("sim2real-va-subnet-")
        subnet_id = ec2.create_subnet(
            VpcId=vpc_id,
            CidrBlock="10.91.1.0/24",
            TagSpecifications=[
                {"ResourceType": "subnet", "Tags": [{"Key": "Name", "Value": subnet_name}]}
            ],
        )["Subnet"]["SubnetId"]
        ctx.on_cleanup(lambda: ec2.delete_subnet(SubnetId=subnet_id))
        subnet_cidr = "10.91.1.0/24"
    sg_name = ctx.unique_name("sim2real-va-sg-")
    sg_id = ec2.create_security_group(
        GroupName=sg_name,
        Description="sim2real verified access sg",
        VpcId=vpc_id,
        TagSpecifications=[
            {"ResourceType": "security-group", "Tags": [{"Key": "Name", "Value": sg_name}]}
        ],
    )["GroupId"]
    ctx.on_cleanup(lambda: _delete_security_group_when_free(ec2, sg_id))

    # AWS always requires Protocol and PortRanges in CidrOptions for a "cidr"
    # verified access endpoint; a minimal CidrOptions (Cidr + SubnetIds only)
    # is rejected server-side with MissingParameter. Note the port-range list
    # member is the plural "PortRanges" (each entry still uses FromPort/ToPort),
    # matching the EC2 API's convention of pluralizing list-of-range members
    # (e.g. AnalysisPacketHeader's DestinationPortRanges/SourcePortRanges);
    # the singular "PortRange" is rejected client-side as an unknown parameter.
    endpoint_name = ctx.unique_name("sim2real-va-endpoint-")
    endpoint_id = ec2.create_verified_access_endpoint(
        AttachmentType="vpc",
        EndpointType="cidr",
        CidrOptions={
            "Cidr": subnet_cidr,
            "Protocol": "tcp",
            "PortRanges": [{"FromPort": 443, "ToPort": 443}],
            "SubnetIds": [subnet_id],
        },
        SecurityGroupIds=[sg_id],
        VerifiedAccessGroupId=group_id,
        TagSpecifications=[
            {
                "ResourceType": "verified-access-endpoint",
                "Tags": [{"Key": "Name", "Value": endpoint_name}],
            }
        ],
    )["VerifiedAccessEndpoint"]["VerifiedAccessEndpointId"]
    ctx.on_cleanup(lambda: ec2.delete_verified_access_endpoint(VerifiedAccessEndpointId=endpoint_id))

    resp = ec2.get_verified_access_endpoint_policy(VerifiedAccessEndpointId=endpoint_id)
    assert "PolicyEnabled" in resp, f"expected a PolicyEnabled field in the response, got {resp!r}"
    assert resp["PolicyEnabled"] is False, "a freshly created endpoint should have no enabled policy"
    assert not resp.get("PolicyDocument"), "a freshly created endpoint should have no policy document"

    bogus_id = "vae-0000000000000000"
    code, message = _error(
        lambda: ec2.get_verified_access_endpoint_policy(VerifiedAccessEndpointId=bogus_id)
    )
    assert code == "InvalidVerifiedAccessEndpointId.NotFound", f"unexpected error code {code!r}"
    expected = f"The verified-access-endpoint ID '{bogus_id}' does not exist"
    assert message == expected, f"expected message {expected!r}, got {message!r}"


def _attach_or_reuse_trust_provider(ec2, ctx, instance_id, trust_provider_id):
    """Attach the given (NativeApplicationOidcOptions) trust provider to the
    instance, falling back to whatever trust provider is already attached if
    the instance is at its (currently 1) trust-provider-attachment limit.

    A TCP-based ("cidr") Verified Access endpoint requires the instance's
    attached trust provider to have NativeApplicationOidcOptions ("TCP based
    endpoints require a TrustProvider with NativeApplicationOidcOptions to be
    attached to the instance."). If the limit is hit and the already-attached
    provider is NOT native-app-capable, swap it out for our native one instead
    of blindly reusing it, restoring the original attachment on cleanup.
    """
    try:
        ec2.attach_verified_access_trust_provider(
            VerifiedAccessInstanceId=instance_id, VerifiedAccessTrustProviderId=trust_provider_id
        )
        ctx.on_cleanup(
            lambda: ec2.detach_verified_access_trust_provider(
                VerifiedAccessInstanceId=instance_id, VerifiedAccessTrustProviderId=trust_provider_id
            )
        )
        return trust_provider_id
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "VerifiedAccessTrustProviderAttachmentLimitExceeded":
            raise

    # The instance is at its trust-provider-attachment limit -- it's a shared,
    # account-wide resource that other concurrently-running checks may also be
    # swapping providers on. So the "currently attached" provider observed via
    # describe_verified_access_instances is only a snapshot: by the time we
    # call detach it can already have been swapped out from under us by a
    # concurrent check, and AWS rejects that detach with InvalidParameterValue
    # ("... is not attached"). Bound-retry by re-reading the live attachment
    # instead of assuming it's stable across the describe-then-detach window.
    for _ in range(10):
        instances = ec2.describe_verified_access_instances(VerifiedAccessInstanceIds=[instance_id])[
            "VerifiedAccessInstances"
        ]
        attached = instances[0].get("VerifiedAccessTrustProviders", []) if instances else []
        if not attached:
            # Nothing attached right now (e.g. a concurrent detach just ran):
            # attach ours directly.
            try:
                ec2.attach_verified_access_trust_provider(
                    VerifiedAccessInstanceId=instance_id, VerifiedAccessTrustProviderId=trust_provider_id
                )
            except ClientError as exc:
                if exc.response["Error"]["Code"] == "VerifiedAccessTrustProviderAttachmentLimitExceeded":
                    time.sleep(0.5)
                    continue  # a concurrent check beat us to the slot; re-check state
                raise
            ctx.on_cleanup(
                lambda: ec2.detach_verified_access_trust_provider(
                    VerifiedAccessInstanceId=instance_id, VerifiedAccessTrustProviderId=trust_provider_id
                )
            )
            return trust_provider_id

        attached_id = attached[0]["VerifiedAccessTrustProviderId"]
        providers = ec2.describe_verified_access_trust_providers(
            VerifiedAccessTrustProviderIds=[attached_id]
        )["VerifiedAccessTrustProviders"]
        if providers and providers[0].get("NativeApplicationOidcOptions"):
            return attached_id

        # The already-attached provider isn't native-app-capable: detach it
        # and attach ours, restoring the original on cleanup. Tolerate the
        # detach racing a concurrent check that already swapped it out from
        # under us -- re-read the live attachment and retry in that case.
        try:
            ec2.detach_verified_access_trust_provider(
                VerifiedAccessInstanceId=instance_id, VerifiedAccessTrustProviderId=attached_id
            )
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "InvalidParameterValue" and "not attached" in str(
                exc
            ).lower():
                time.sleep(0.5)
                continue  # raced with a concurrent detach/attach; re-read state and retry
            raise

        try:
            ec2.attach_verified_access_trust_provider(
                VerifiedAccessInstanceId=instance_id, VerifiedAccessTrustProviderId=trust_provider_id
            )
        except ClientError:
            # Restore what we just detached before giving up/retrying.
            ec2.attach_verified_access_trust_provider(
                VerifiedAccessInstanceId=instance_id, VerifiedAccessTrustProviderId=attached_id
            )
            raise

        def _restore(_attached_id=attached_id):
            ec2.detach_verified_access_trust_provider(
                VerifiedAccessInstanceId=instance_id, VerifiedAccessTrustProviderId=trust_provider_id
            )
            ec2.attach_verified_access_trust_provider(
                VerifiedAccessInstanceId=instance_id, VerifiedAccessTrustProviderId=_attached_id
            )

        ctx.on_cleanup(_restore)
        return trust_provider_id

    raise RuntimeError(
        "could not attach the verified access trust provider: the shared instance's "
        "attachment kept racing with a concurrent check across all retries"
    )


def _get_or_create_verified_access_instance(ec2, ctx):
    """Create a Verified Access instance, falling back to an existing one if the
    account is already at the instance-count limit."""
    try:
        instance_name = ctx.unique_name("sim2real-va-instance-")
        instance_id = ec2.create_verified_access_instance(
            Description=instance_name,
            TagSpecifications=[
                {"ResourceType": "verified-access-instance", "Tags": [{"Key": "Name", "Value": instance_name}]}
            ],
        )["VerifiedAccessInstance"]["VerifiedAccessInstanceId"]
        ctx.on_cleanup(lambda: ec2.delete_verified_access_instance(VerifiedAccessInstanceId=instance_id))
        return instance_id
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "VerifiedAccessInstanceLimitExceeded":
            raise
        instances = ec2.describe_verified_access_instances()["VerifiedAccessInstances"]
        if not instances:
            raise
        return instances[0]["VerifiedAccessInstanceId"]


def _existing_vpc_and_subnet(ec2, *, ctx):
    """Find an existing VPC with at least one subnet, to avoid hitting the account VPC limit."""
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError(f"the run's shared network {ctx.network().vpc_id} is not visible")
    for vpc in vpcs:
        subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc["VpcId"]]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
        if subnets:
            return vpc["VpcId"], subnets[0]["SubnetId"], subnets[0]["CidrBlock"]
    return None, None, None


def _error(fn):
    """Call fn(); return the (code, message) of the ClientError it raises. A success raises
    AssertionError: a target that accepts what AWS refuses fails loudly here."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")



def _delete_security_group_when_free(ec2, sg_id, timeout_s=900.0, interval_s=15.0):
    """Delete a security group once the ENIs still holding it are released (DependencyViolation)."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            ec2.delete_security_group(GroupId=sg_id)
            return
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code == "InvalidGroup.NotFound":
                return
            if code != "DependencyViolation" or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)

if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
