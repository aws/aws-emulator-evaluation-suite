"""op-contract-export-verified-access-instance-client-configuration."""
from __future__ import annotations

import time
from typing import Any, Callable

from behavioral_harness import tags

CHECK = "op-contract-export-verified-access-instance-client-configuration"
GROUP = "error-semantics"
SERVICES = ["ec2"]

# The exact message EC2 returns for every DryRun call the caller is authorised for.
_DRY_RUN_MESSAGE = "Request would have succeeded, but DryRun flag is set."


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ExportVerifiedAccessInstanceClientConfiguration, on an instance with an active TCP endpoint,
    returns the requested VerifiedAccessInstanceId and the caller's Region; with DryRun it fails
    with DryRunOperation and the standard DryRun message."""

    ec2 = ctx.client("ec2")

    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError(f"the run's shared network {ctx.network().vpc_id} is not visible")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    if not subnets:
        raise AssertionError("no subnet available to host a Verified Access endpoint's network interface")
    subnet_id = subnets[0]["SubnetId"]

    instance_id = ec2.create_verified_access_instance(
        Description=ctx.unique_name("sim2real-vai-"),
        TagSpecifications=[{
            "ResourceType": "verified-access-instance",
            "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-vai-")}],
        }],
    )["VerifiedAccessInstance"]["VerifiedAccessInstanceId"]
    ctx.on_cleanup(lambda: ec2.delete_verified_access_instance(VerifiedAccessInstanceId=instance_id))
    _wait_for(lambda: _instance_exists(ec2, instance_id), timeout_s=60)

    # A Verified Access instance must have a trust provider attached before it will
    # allow creating a group/endpoint on it (CreateVerifiedAccessGroup fails with
    # "Must attach a TrustProvider to Instance ..." otherwise). An OIDC user trust
    # provider needs no functioning IdP for creation/attachment -- its endpoints are
    # just stored configuration -- so it's usable without external dependencies.
    # TCP-based endpoints specifically require the trust provider to carry
    # "native application" OIDC options (real AWS rejects CreateVerifiedAccessEndpoint
    # for a TCP endpoint with InvalidParameterValue: "TCP based endpoints require a
    # TrustProvider with NativeApp" when only the browser-flavored OidcOptions is set).
    trust_provider_id = ec2.create_verified_access_trust_provider(
        TrustProviderType="user",
        UserTrustProviderType="oidc",
        NativeApplicationOidcOptions={
            "PublicSigningKeyEndpoint": "https://sim2real.example.com/keys",
            "Issuer": "https://sim2real.example.com",
            "AuthorizationEndpoint": "https://sim2real.example.com/authorize",
            "TokenEndpoint": "https://sim2real.example.com/token",
            "UserInfoEndpoint": "https://sim2real.example.com/userinfo",
            "ClientId": "sim2real-client-id",
            "ClientSecret": "sim2real-client-secret",
            "Scope": "openid",
        },
        PolicyReferenceName="sim2real",
    )["VerifiedAccessTrustProvider"]["VerifiedAccessTrustProviderId"]
    ctx.on_cleanup(lambda: ec2.delete_verified_access_trust_provider(
        VerifiedAccessTrustProviderId=trust_provider_id))

    ec2.attach_verified_access_trust_provider(
        VerifiedAccessInstanceId=instance_id,
        VerifiedAccessTrustProviderId=trust_provider_id,
    )
    ctx.on_cleanup(lambda: ec2.detach_verified_access_trust_provider(
        VerifiedAccessInstanceId=instance_id, VerifiedAccessTrustProviderId=trust_provider_id))

    sg_id = ec2.create_security_group(
        GroupName=ctx.unique_name("sim2real-vaisg-"),
        Description="sim2real verified-access endpoint test",
        VpcId=vpc_id,
    )["GroupId"]
    ctx.on_cleanup(lambda: _delete_security_group_when_released(ec2, sg_id))

    # Real AWS never promotes a network-interface Verified Access endpoint out of
    # "pending" when its backing ENI is a bare, unattached interface (a standalone
    # ENI created via CreateNetworkInterface stays in the "available" attachment
    # state forever, since nothing ever attaches it) -- the endpoint's readiness
    # checks apparently require the target ENI to actually be attached to a live
    # resource. Back the endpoint with the primary ENI of a freshly launched
    # instance instead: RunInstances attaches the primary network interface
    # immediately (attachment status "attached") well before the instance itself
    # finishes booting, so we don't need to wait for the instance to be "running".
    images = ec2.describe_images(
        Owners=["amazon"],
        Filters=[
            {"Name": "name", "Values": ["al2023-ami-*-x86_64"]},
            {"Name": "state", "Values": ["available"]},
            {"Name": "root-device-type", "Values": ["ebs"]},
            {"Name": "virtualization-type", "Values": ["hvm"]},
        ],
    )["Images"]
    if not images:
        raise AssertionError("no Amazon Linux 2023 AMI available to back a live network interface for the endpoint")
    images.sort(key=lambda i: i.get("CreationDate", ""), reverse=True)
    ami_id = images[0]["ImageId"]

    run_resp = ec2.run_instances(
        ImageId=ami_id,
        InstanceType="t3.micro",
        MinCount=1,
        MaxCount=1,
        SubnetId=subnet_id,
        SecurityGroupIds=[sg_id],
    )
    backing_instance_id = run_resp["Instances"][0]["InstanceId"]
    ctx.on_cleanup(lambda: _terminate_and_wait(ec2, backing_instance_id))
    eni_id = run_resp["Instances"][0]["NetworkInterfaces"][0]["NetworkInterfaceId"]

    group_id = ec2.create_verified_access_group(
        VerifiedAccessInstanceId=instance_id
    )["VerifiedAccessGroup"]["VerifiedAccessGroupId"]
    ctx.on_cleanup(lambda: ec2.delete_verified_access_group(VerifiedAccessGroupId=group_id))

    # For the "tcp" protocol, EniOptions must carry PortRanges (a list of
    # FromPort/ToPort objects) rather than a single Port -- CreateVerifiedAccessEndpoint
    # rejects "Port" with InvalidParameterValue when Protocol is 'tcp' (Port is only
    # valid for http/https network-interface endpoints), and the parameter for the
    # tcp case is named "PortRanges" (plural, a list), not "PortRange".
    endpoint_id = ec2.create_verified_access_endpoint(
        AttachmentType="vpc",
        EndpointType="network-interface",
        VerifiedAccessGroupId=group_id,
        SecurityGroupIds=[sg_id],
        NetworkInterfaceOptions={
            "NetworkInterfaceId": eni_id,
            "Protocol": "tcp",
            "PortRanges": [{"FromPort": 443, "ToPort": 443}],
        },
    )["VerifiedAccessEndpoint"]["VerifiedAccessEndpointId"]
    ctx.on_cleanup(lambda: _delete_endpoint_and_wait(ec2, endpoint_id))
    # AWS can take well over ten minutes to bring a new network-interface Verified Access endpoint
    # to "active" (its PrivateLink-style plumbing is provisioned asynchronously), so the wait is long.
    _wait_for(
        lambda: _endpoint_active(ec2, endpoint_id),
        timeout_s=1150,
        interval_s=5.0,
        detail=lambda: _endpoint_status_detail(ec2, endpoint_id),
    )

    # --- success path: exported config identifies this exact instance and region ---
    resp = ec2.export_verified_access_instance_client_configuration(
        VerifiedAccessInstanceId=instance_id
    )
    assert resp["VerifiedAccessInstanceId"] == instance_id, (
        f"expected VerifiedAccessInstanceId {instance_id!r}, got {resp.get('VerifiedAccessInstanceId')!r}"
    )
    assert resp["Region"] == ctx.region, f"expected Region {ctx.region!r}, got {resp.get('Region')!r}"

    # --- error boundary: DryRun permission-check contract ---
    code, message = _error(lambda: ec2.export_verified_access_instance_client_configuration(
        VerifiedAccessInstanceId=instance_id, DryRun=True
    ))
    assert code == "DryRunOperation", f"expected DryRunOperation, got {code!r}"
    assert message == _DRY_RUN_MESSAGE, message


def _instance_exists(ec2: Any, instance_id: str) -> bool:
    resp = ec2.describe_verified_access_instances(VerifiedAccessInstanceIds=[instance_id])
    return len(resp["VerifiedAccessInstances"]) == 1


def _endpoint_active(ec2: Any, endpoint_id: str) -> bool:
    resp = ec2.describe_verified_access_endpoints(VerifiedAccessEndpointIds=[endpoint_id])
    endpoints = resp["VerifiedAccessEndpoints"]
    if not endpoints:
        return False
    return endpoints[0]["Status"]["Code"] == "active"


def _endpoint_status_detail(ec2: Any, endpoint_id: str) -> str:
    resp = ec2.describe_verified_access_endpoints(VerifiedAccessEndpointIds=[endpoint_id])
    endpoints = resp["VerifiedAccessEndpoints"]
    if not endpoints:
        return "endpoint no longer describable"
    return repr(endpoints[0]["Status"])


def _delete_endpoint_and_wait(ec2: Any, endpoint_id: str, timeout_s: float = 900.0) -> None:
    """Delete the Verified Access endpoint and wait until it is gone, so the network
    interfaces it holds in the security group are released before the group's teardown."""
    from botocore.exceptions import ClientError
    try:
        ec2.delete_verified_access_endpoint(VerifiedAccessEndpointId=endpoint_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "InvalidVerifiedAccessEndpointId.NotFound":
            raise
        return
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            endpoints = ec2.describe_verified_access_endpoints(
                VerifiedAccessEndpointIds=[endpoint_id])["VerifiedAccessEndpoints"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "InvalidVerifiedAccessEndpointId.NotFound":
                return
            raise
        if not endpoints or endpoints[0]["Status"]["Code"] == "deleted":
            return
        time.sleep(10)
    raise AssertionError(f"Verified Access endpoint {endpoint_id} was not deleted within {timeout_s}s")


def _terminate_and_wait(ec2: Any, instance_id: str) -> None:
    """Terminate the backing instance and wait until it is terminated, so its primary
    network interface no longer holds the security group."""
    ec2.terminate_instances(InstanceIds=[instance_id])
    ec2.get_waiter("instance_terminated").wait(
        InstanceIds=[instance_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})


def _delete_security_group_when_released(ec2: Any, group_id: str, timeout_s: float = 600.0) -> None:
    """Delete the security group, retrying while a just-deleted dependant still holds it."""
    from botocore.exceptions import ClientError
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            ec2.delete_security_group(GroupId=group_id)
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "InvalidGroup.NotFound":
                return
            if code != "DependencyViolation" or time.monotonic() >= deadline:
                raise
        time.sleep(15)


def _wait_for(
    predicate: Callable[[], bool],
    timeout_s: float = 60.0,
    interval_s: float = 2.0,
    detail: Callable[[], str] | None = None,
) -> None:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(interval_s)
    extra = f" -- last observed: {detail()}" if detail is not None else ""
    raise AssertionError(f"condition not met within {timeout_s}s{extra}")


def _error(fn: Callable[[], Any]) -> tuple[str, str]:
    """Call fn() and return the (code, message) of the ClientError it raises. A call
    that succeeds raises AssertionError, because an emulator accepting what real AWS
    refuses must not read as a mere code mismatch."""
    from botocore.exceptions import ClientError
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
