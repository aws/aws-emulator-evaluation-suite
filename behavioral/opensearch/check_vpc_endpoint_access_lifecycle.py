"""vpc-endpoint-access-lifecycle."""
from __future__ import annotations

import random
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "vpc-endpoint-access-lifecycle"
GROUP = 'vpc-endpoint'
SERVICES = ['opensearch']

ENGINE_VERSION = 'OpenSearch_2.11'
_THROTTLE_CODES = ("ThrottlingException", "TooManyRequestsException", "RequestLimitExceeded")


def _ec2_tag_specs(resource_type: str) -> list:
    return [{
        "ResourceType": resource_type,
        "Tags": [{"Key": "sim2real", "Value": "behav"}],
    }]


def _own_vpc_subnet_and_sg(ctx, ec2) -> "tuple[str, str, str]":
    """A VPC, subnet and security group this check creates, so the domain never depends on an
    account default VPC."""
    vpc_id = ec2.create_vpc(
        CidrBlock="10.93.0.0/16", TagSpecifications=_ec2_tag_specs("vpc")
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc_id))
    az = ec2.describe_availability_zones()["AvailabilityZones"][0]["ZoneName"]
    subnet_id = ec2.create_subnet(
        VpcId=vpc_id,
        CidrBlock="10.93.1.0/24",
        AvailabilityZone=az,
        TagSpecifications=_ec2_tag_specs("subnet"),
    )["Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_subnet", SubnetId=subnet_id))
    sg_id = ec2.create_security_group(
        GroupName=ctx.unique_name("sim2real-behav-sg-"),
        Description="sim2real behavioral opensearch vpc endpoint sg",
        VpcId=vpc_id,
        TagSpecifications=_ec2_tag_specs("security-group"),
    )["GroupId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_security_group", GroupId=sg_id))
    return vpc_id, subnet_id, sg_id


def _ensure_vpc_service_linked_role(ctx) -> None:
    """A VPC-attached CreateDomain needs the ``es.amazonaws.com`` service-linked role and does not
    create it; create it so the check is account-independent. ``InvalidInput`` is the
    already-exists answer."""
    try:
        ctx.client("iam").create_service_linked_role(AWSServiceName="es.amazonaws.com")
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") not in ("InvalidInput", "InvalidInputException"):
            raise


def _create_domain(ctx, osc, domain_name, *, vpc_options) -> dict:
    kwargs = dict(
        DomainName=domain_name,
        EngineVersion=ENGINE_VERSION,
        ClusterConfig={
            "InstanceType": "t3.small.search",
            "InstanceCount": 1,
            "DedicatedMasterEnabled": False,
            "ZoneAwarenessEnabled": False,
        },
        EBSOptions={"EBSEnabled": True, "VolumeType": "gp2", "VolumeSize": 10},
        VPCOptions=vpc_options,
    )
    for _attempt in range(12):
        try:
            resp = osc.create_domain(**kwargs)
            break
        except ClientError as _e:
            if _e.response.get("Error", {}).get("Code") not in _THROTTLE_CODES:
                raise
            time.sleep(6.0 * (1 + _attempt) + random.uniform(0, 6.0))
    else:
        raise AssertionError("still throttled after 12 attempts")
    ctx.on_cleanup(lambda: osc.delete_domain(DomainName=domain_name))
    return resp["DomainStatus"]


def _wait_domain_active(osc, domain_name, timeout_s: float = 1450) -> dict:
    """Poll until Processing=False and Created=True, raising once ``timeout_s`` passes."""
    budget = timeout_s
    deadline = time.monotonic() + budget
    last = None
    while time.monotonic() < deadline:
        last = osc.describe_domain(DomainName=domain_name)["DomainStatus"]
        if last.get("Processing") is False and last.get("Created") is True:
            return last
        time.sleep(2)
    raise AssertionError(f"domain {domain_name} never became Active within {budget}s")


def _error(fn) -> "tuple[str, str]":
    """Call fn() and return the (Code, Message) of the ClientError it raises; raise if it succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError(f"expected a ClientError, the call succeeded with {result!r}")


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """AuthorizeVpcEndpointAccess grants a service principal access to a VPC domain, visible via
    ListVpcEndpointAccess; RevokeVpcEndpointAccess removes it; a missing domain is refused."""
    osc = ctx.client("opensearch")
    ec2 = ctx.client("ec2")

    # The API is VPC-domain only (a public domain raises ValidationException).
    _ensure_vpc_service_linked_role(ctx)
    _vpc_id, subnet_id, sg_id = _own_vpc_subnet_and_sg(ctx, ec2)

    domain = ctx.unique_name("sim2real-behav-os-")[:28].rstrip("-")
    _create_domain(
        ctx, osc, domain,
        vpc_options={"SubnetIds": [subnet_id], "SecurityGroupIds": [sg_id]},
    )
    _wait_domain_active(osc, domain)

    # The OpenSearch UI application service principal is the documented grantee.
    grantee_service = "application.opensearchservice.amazonaws.com"
    authorized = osc.authorize_vpc_endpoint_access(
        DomainName=domain, Service=grantee_service
    )["AuthorizedPrincipal"]
    ctx.on_cleanup(
        lambda: osc.revoke_vpc_endpoint_access(DomainName=domain, Service=grantee_service)
    )
    assert grantee_service in authorized["Principal"], (
        f"expected {grantee_service!r} in AuthorizedPrincipal.Principal, got {authorized.get('Principal')!r}"
    )
    # The model's PrincipalType enum is AWS_ACCOUNT/AWS_SERVICE, but the API returns
    # the human-readable "AWS Service".
    assert authorized.get("PrincipalType") == "AWS Service", (
        f"expected PrincipalType 'AWS Service' for a Service grantee, got {authorized.get('PrincipalType')!r}"
    )

    listed = osc.list_vpc_endpoint_access(DomainName=domain)["AuthorizedPrincipalList"]
    assert any(grantee_service in p["Principal"] for p in listed), (
        f"expected {grantee_service!r} in ListVpcEndpointAccess, got {listed!r}"
    )

    osc.revoke_vpc_endpoint_access(DomainName=domain, Service=grantee_service)

    listed_after = osc.list_vpc_endpoint_access(DomainName=domain)["AuthorizedPrincipalList"]
    assert not any(grantee_service in p["Principal"] for p in listed_after), (
        f"expected {grantee_service!r} absent from ListVpcEndpointAccess after revoke, got {listed_after!r}"
    )

    # Authorizing access on a nonexistent domain must fail, not create a dangling grant.
    bogus_domain = ctx.unique_name("sim2real-behav-os-missing-")[:28].rstrip("-")
    code, message = _error(
        lambda: osc.authorize_vpc_endpoint_access(DomainName=bogus_domain, Service=grantee_service)
    )
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code}"
    expected_message = (
        "Either the domain doesn't exist, it doesn't support creation of VPC endpoints, or you "
        "don't have permission to create a VPC endpoint for the domain."
    )
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"


# The domain deletes asynchronously and its ENIs linger, so an immediate DeleteSubnet /
# DeleteSecurityGroup / DeleteVpc fails with DependencyViolation. Teardown waits for the ENIs
# (one bounded window shared by all network deletes), retries, then raises naming the ENIs.
_NET_TEARDOWN_S = 630.0
_NET_ENI_FILTER = {"VpcId": "vpc-id", "SubnetId": "subnet-id", "GroupId": "group-id"}
_NET_DEADLINES: dict = {}


def _delete_net(client, op, **ident):
    import time as _time

    from botocore.exceptions import ClientError as _ClientError

    held = _NET_DEADLINES.get(id(client))
    if held is None or held[0] is not client:
        held = _NET_DEADLINES[id(client)] = (client, _time.monotonic() + _NET_TEARDOWN_S)
    deadline = held[1]
    flt = [{"Name": _NET_ENI_FILTER[k], "Values": [v]} for k, v in ident.items() if k in _NET_ENI_FILTER]
    while _net_enis(client, flt) and _time.monotonic() < deadline:
        _time.sleep(10)
    while True:
        try:
            return getattr(client, op)(**ident)
        except _ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            if code != "DependencyViolation":
                raise
            if _time.monotonic() >= deadline:
                # Same exception type and code, so a caller catching ClientError still collects it.
                raise type(exc)(
                    {**exc.response, "Error": {**exc.response.get("Error", {}), "Message": (
                        f"{op}({ident}): DependencyViolation after {_NET_TEARDOWN_S}s; "
                        f"ENIs still attached: {_net_enis(client, flt)}"
                    )}},
                    exc.operation_name,
                ) from exc
        _time.sleep(10)


def _net_enis(client, flt):
    from botocore.exceptions import ClientError as _ClientError

    if not flt:
        return []
    try:
        enis = client.describe_network_interfaces(Filters=flt)["NetworkInterfaces"]
    except _ClientError:
        return []  # a diagnostic only: the delete itself still reports its own failure
    return [f"{e['NetworkInterfaceId']}:{e.get('InterfaceType') or e.get('Description', '')[:40]}" for e in enis]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
