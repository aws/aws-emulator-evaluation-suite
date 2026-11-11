"""op-contract-deleteVerifiedAccessEndpoint."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-deleteVerifiedAccessEndpoint"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeleteVerifiedAccessEndpoint tears down a cidr-type endpoint; re-deleting the same endpoint is rejected NotFound."""
    ec2 = ctx.client("ec2")

    vpc_id = ec2.create_vpc(
        CidrBlock="10.211.0.0/16", TagSpecifications=[_tag_spec(ctx, "vpc", "vae-vpc")]
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _retry_delete(lambda: ec2.delete_vpc(VpcId=vpc_id)))

    subnet_id = ec2.create_subnet(
        VpcId=vpc_id, CidrBlock="10.211.1.0/24", TagSpecifications=[_tag_spec(ctx, "subnet", "vae-subnet")]
    )["Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda: _retry_delete(lambda: ec2.delete_subnet(SubnetId=subnet_id)))

    sg_id = ec2.create_security_group(
        GroupName=ctx.unique_name("sim2real-vae-sg-"),
        Description="sim2real behavioral check",
        VpcId=vpc_id,
        TagSpecifications=[_tag_spec(ctx, "security-group", "vae-sg")],
    )["GroupId"]
    ctx.on_cleanup(lambda: _retry_delete(lambda: ec2.delete_security_group(GroupId=sg_id)))

    instance_id = ec2.create_verified_access_instance(
        TagSpecifications=[_tag_spec(ctx, "verified-access-instance", "vae-inst")]
    )["VerifiedAccessInstance"]["VerifiedAccessInstanceId"]
    ctx.on_cleanup(lambda: _safe(lambda: ec2.delete_verified_access_instance(VerifiedAccessInstanceId=instance_id)))

    # a verified-access instance must have a trust provider attached before a group can be created
    trust_provider_id = ec2.create_verified_access_trust_provider(
        TrustProviderType="user",
        UserTrustProviderType="oidc",
        PolicyReferenceName="sim2realvaetp",
        OidcOptions={
            "Issuer": "https://sim2real.example.com/oidc",
            "AuthorizationEndpoint": "https://sim2real.example.com/oidc/authorize",
            "TokenEndpoint": "https://sim2real.example.com/oidc/token",
            "UserInfoEndpoint": "https://sim2real.example.com/oidc/userinfo",
            "ClientId": "sim2real-client-id",
            "ClientSecret": "sim2real-client-secret",
            "Scope": "openid",
        },
        # TCP-based (cidr) verified access endpoints require the trust provider to also
        # carry NativeApplicationOidcOptions, since those endpoints have no browser to
        # perform a redirect-based OIDC flow.
        NativeApplicationOidcOptions=_build_native_app_oidc_options(ec2),
        TagSpecifications=[_tag_spec(ctx, "verified-access-trust-provider", "vae-tp")],
    )["VerifiedAccessTrustProvider"]["VerifiedAccessTrustProviderId"]
    ctx.on_cleanup(
        lambda: _safe(lambda: ec2.delete_verified_access_trust_provider(VerifiedAccessTrustProviderId=trust_provider_id))
    )
    ec2.attach_verified_access_trust_provider(
        VerifiedAccessInstanceId=instance_id, VerifiedAccessTrustProviderId=trust_provider_id
    )
    ctx.on_cleanup(
        lambda: _safe(
            lambda: ec2.detach_verified_access_trust_provider(
                VerifiedAccessInstanceId=instance_id, VerifiedAccessTrustProviderId=trust_provider_id
            )
        )
    )

    group_id = ec2.create_verified_access_group(
        VerifiedAccessInstanceId=instance_id,
        TagSpecifications=[_tag_spec(ctx, "verified-access-group", "vae-group")],
    )["VerifiedAccessGroup"]["VerifiedAccessGroupId"]
    ctx.on_cleanup(lambda: _safe(lambda: ec2.delete_verified_access_group(VerifiedAccessGroupId=group_id)))

    created = ec2.create_verified_access_endpoint(
        AttachmentType="vpc",
        EndpointType="cidr",
        CidrOptions=_build_cidr_options(ec2, "10.211.2.0/24", subnet_id),
        SecurityGroupIds=[sg_id],
        VerifiedAccessGroupId=group_id,
        TagSpecifications=[_tag_spec(ctx, "verified-access-endpoint", "vae")],
    )
    endpoint_id = created["VerifiedAccessEndpoint"]["VerifiedAccessEndpointId"]
    state = {"deleted": False}

    def _cleanup_endpoint():
        if not state["deleted"]:
            _safe(lambda: ec2.delete_verified_access_endpoint(VerifiedAccessEndpointId=endpoint_id))

    ctx.on_cleanup(_cleanup_endpoint)

    # The group association is set synchronously by CreateVerifiedAccessEndpoint and
    # does not require waiting for the endpoint to leave "pending"/"creating" -- that
    # transition provisions real underlying network infrastructure and can take
    # far longer than a check's budget. DeleteVerifiedAccessEndpoint is defined to tear the endpoint down
    # regardless of its current provisioning state (a still-"pending"/"creating"
    # endpoint transitions straight to "deleting"), so the delete-contract test
    # below does not need to wait for activation first.
    assert created["VerifiedAccessEndpoint"]["VerifiedAccessGroupId"] == group_id

    ec2.delete_verified_access_endpoint(VerifiedAccessEndpointId=endpoint_id)
    state["deleted"] = True

    def _probe_deleted():
        try:
            described = ec2.describe_verified_access_endpoints(VerifiedAccessEndpointIds=[endpoint_id])
            if not described["VerifiedAccessEndpoints"]:
                return "gone"
            return described["VerifiedAccessEndpoints"][0]["Status"]["Code"]
        except ClientError as exc:
            if exc.response["Error"]["Code"].startswith("Invalid"):
                return "gone"
            raise

    # Real AWS has been observed to leave a deleted cidr-type endpoint in "deleting"
    # for well beyond two minutes -- the same underlying network-infrastructure
    # teardown that makes activation slow (see the comment above) also makes
    # deletion slow. Poll with a generous budget rather than shortening the wait
    # or accepting "deleting" as a terminal state.
    _poll_until(_probe_deleted, lambda code: code in ("deleted", "gone"), timeout_s=1800.0, interval_s=10.0)

    # distinct error boundary: re-deleting the already-deleted endpoint is rejected NotFound
    code, message = _error(lambda: ec2.delete_verified_access_endpoint(VerifiedAccessEndpointId=endpoint_id))
    assert code == "InvalidVerifiedAccessEndpointId.NotFound", f"unexpected error re-deleting an endpoint: {code}: {message}"
    assert message == f"The verified-access-endpoint ID '{endpoint_id}' does not exist", message


# ===== helpers =====
def _build_cidr_options(ec2, cidr: str, subnet_id: str) -> dict:
    """Build the CidrOptions payload from the client's own service model instead of
    hardcoding member names; the exact set/spelling of members has shifted across
    botocore releases for this recently-added endpoint type, and a stale guess raises
    a client-side ParamValidationError before the request ever reaches AWS."""
    op_model = ec2.meta.service_model.operation_model("CreateVerifiedAccessEndpoint")
    cidr_shape = op_model.input_shape.members["CidrOptions"]
    members = cidr_shape.members
    options: dict = {}
    for key in members:
        if key == "Cidr":
            options[key] = cidr
        elif key == "Protocol":
            options[key] = "tcp"
        elif key == "SubnetIds":
            options[key] = [subnet_id]
        elif key.lower().startswith("port"):
            item_shape = members[key].member
            item_members = list(item_shape.members.keys())
            from_key = next((m for m in item_members if "From" in m), item_members[0])
            to_key = next((m for m in item_members if "To" in m), item_members[-1])
            options[key] = [{from_key: 443, to_key: 443}]
    return options


def _build_native_app_oidc_options(ec2) -> dict:
    """Build the NativeApplicationOidcOptions payload from the client's own service
    model instead of hardcoding member names; TCP-based (cidr) endpoints require the
    attached trust provider to carry this in addition to OidcOptions, since a native
    (non-browser) client can't perform a redirect-based OIDC flow."""
    op_model = ec2.meta.service_model.operation_model("CreateVerifiedAccessTrustProvider")
    shape = op_model.input_shape.members["NativeApplicationOidcOptions"]
    members = shape.members
    options: dict = {}
    for key in members:
        lk = key.lower()
        if lk == "issuer":
            options[key] = "https://sim2real.example.com/oidc"
        elif "authorization" in lk:
            options[key] = "https://sim2real.example.com/oidc/authorize"
        elif "publicsigningkey" in lk:
            options[key] = "https://sim2real.example.com/oidc/jwks"
        elif lk.startswith("token"):
            options[key] = "https://sim2real.example.com/oidc/token"
        elif "userinfo" in lk:
            options[key] = "https://sim2real.example.com/oidc/userinfo"
        elif lk == "clientid":
            options[key] = "sim2real-client-id"
        elif lk == "clientsecret":
            options[key] = "sim2real-client-secret"
        elif lk == "scope":
            options[key] = "openid"
    return options


def _tag_spec(ctx, resource_type: str, prefix: str) -> dict:
    return {
        "ResourceType": resource_type,
        "Tags": [{"Key": "Name", "Value": ctx.unique_name(f"sim2real-{prefix}-")}],
    }


def _error(fn):
    """Call fn() and return its ClientError (code, message); an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message")
    raise AssertionError(f"expected a rejection, but the call succeeded and returned {result!r}")


def _safe(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "InvalidVerifiedAccessEndpointId.NotFound",
            "InvalidVerifiedAccessGroupId.NotFound",
            "InvalidVerifiedAccessInstanceId.NotFound",
            "InvalidVerifiedAccessTrustProviderId.NotFound",
        ):
            raise


def _retry_delete(fn, timeout_s: float = 240.0):
    """Delete, retrying DependencyViolation every 2 s for up to timeout_s while the endpoint's network interfaces
    release; a resource already gone returns; any other error raises."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            fn()
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code in ("InvalidVpcID.NotFound", "InvalidSubnetID.NotFound", "InvalidGroup.NotFound"):
                return
            if code != "DependencyViolation" or time.monotonic() >= deadline:
                raise
        time.sleep(2)


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last value={last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
