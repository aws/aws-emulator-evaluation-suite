"""create-client-vpn-route-conflicting-destination-rejected."""
from __future__ import annotations

import os
import subprocess
import tempfile
import time

from behavioral_harness import tags
from fidelity_tests_runner import require_tools

CHECK = "create-client-vpn-route-conflicting-destination-rejected"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A duplicate (destination CIDR, subnet) CreateClientVpnRoute is rejected with
    InvalidClientVpnDuplicateRoute and leaves one route, a different CIDR to the same subnet is
    created and listed once, and after deleting the original the identical route is created again."""
    ec2 = ctx.client("ec2")

    az = ec2.describe_availability_zones(
        Filters=[{"Name": "state", "Values": ["available"]}]
    )["AvailabilityZones"][0]["ZoneName"]
    vpc_id = ec2.create_vpc(CidrBlock="10.211.0.0/16")["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc_id))
    subnet_id = ec2.create_subnet(
        VpcId=vpc_id, CidrBlock="10.211.1.0/24", AvailabilityZone=az
    )["Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_subnet", SubnetId=subnet_id))
    sg_id = ec2.create_security_group(
        VpcId=vpc_id, GroupName=ctx.unique_name("sim2real-cvpn-dup-sg-"), Description="sim2real"
    )["GroupId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_security_group", GroupId=sg_id))

    cert_arn = _import_self_signed_cert(ctx)

    endpoint_id = _create_client_vpn_endpoint_with_retry(
        ec2,
        ClientCidrBlock="10.212.0.0/22",
        ServerCertificateArn=cert_arn,
        AuthenticationOptions=[
            {
                "Type": "certificate-authentication",
                "MutualAuthentication": {"ClientRootCertificateChainArn": cert_arn},
            }
        ],
        ConnectionLogOptions={"Enabled": False},
        TagSpecifications=[
            {
                "ResourceType": "client-vpn-endpoint",
                "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-behav-cvpn-")}],
            }
        ],
    )["ClientVpnEndpointId"]
    # The endpoint cannot be deleted until its target network has finished disassociating.
    ctx.on_cleanup(lambda: _retry_teardown(
        lambda: ec2.delete_client_vpn_endpoint(ClientVpnEndpointId=endpoint_id),
        ("IncorrectState", "InvalidClientVpnEndpointState", "InvalidState"),
        timeout_s=600.0,
    ))
    ec2.apply_security_groups_to_client_vpn_target_network(
        ClientVpnEndpointId=endpoint_id, VpcId=vpc_id, SecurityGroupIds=[sg_id]
    )

    assoc_id = ec2.associate_client_vpn_target_network(
        ClientVpnEndpointId=endpoint_id, SubnetId=subnet_id
    )["AssociationId"]
    ctx.on_cleanup(lambda: _retry_teardown(
        lambda: ec2.disassociate_client_vpn_target_network(
            ClientVpnEndpointId=endpoint_id, AssociationId=assoc_id
        ),
        ("IncorrectState", "InvalidClientVpnAssociationIdState", "InvalidState"),
    ))

    _poll_until(
        lambda: ec2.describe_client_vpn_target_networks(
            ClientVpnEndpointId=endpoint_id, AssociationIds=[assoc_id]
        )["ClientVpnTargetNetworks"][0]["Status"]["Code"],
        lambda code: code == "associated",
        timeout_s=600,
        interval_s=10,
    )

    dest_cidr = "10.55.0.0/16"
    ec2.create_client_vpn_route(
        ClientVpnEndpointId=endpoint_id,
        DestinationCidrBlock=dest_cidr,
        TargetVpcSubnetId=subnet_id,
    )
    _poll_until(
        lambda: _route_status(ec2, endpoint_id, dest_cidr),
        lambda code: code in ("active", "pending"),
        timeout_s=120,
        interval_s=3,
    )

    # Negative: creating the identical route again is rejected as a duplicate.
    code, message = _error(
        lambda: ec2.create_client_vpn_route(
            ClientVpnEndpointId=endpoint_id,
            DestinationCidrBlock=dest_cidr,
            TargetVpcSubnetId=subnet_id,
        )
    )
    assert code == "InvalidClientVpnDuplicateRoute", (
        f"expected InvalidClientVpnDuplicateRoute, got {code!r}"
    )
    assert message == "Route already exists", f"duplicate route message: {message!r}"

    # Effect absence: still exactly one route for that destination.
    routes = ec2.describe_client_vpn_routes(
        ClientVpnEndpointId=endpoint_id,
        Filters=[{"Name": "destination-cidr", "Values": [dest_cidr]}],
    )["Routes"]
    assert len(routes) == 1, f"expected exactly 1 route for {dest_cidr}, found {len(routes)}"

    # Positive control: a route to a different destination CIDR on the same subnet
    # succeeds -- the rejection above is specific to the duplicate, not a blanket
    # refusal of CreateClientVpnRoute on this endpoint/subnet.
    other_cidr = "10.77.0.0/16"
    ec2.create_client_vpn_route(
        ClientVpnEndpointId=endpoint_id,
        DestinationCidrBlock=other_cidr,
        TargetVpcSubnetId=subnet_id,
    )
    _poll_until(
        lambda: _route_status(ec2, endpoint_id, other_cidr),
        lambda code: code in ("active", "pending"),
        timeout_s=120,
        interval_s=3,
    )
    other_routes = ec2.describe_client_vpn_routes(
        ClientVpnEndpointId=endpoint_id,
        Filters=[{"Name": "destination-cidr", "Values": [other_cidr]}],
    )["Routes"]
    assert len(other_routes) == 1, (
        f"expected exactly 1 route for {other_cidr}, found {len(other_routes)}"
    )

    # Restore: the rejection is tied to the conflicting state, not to the (destination,
    # subnet) pair permanently. Delete the original route, then the identical call that
    # was just rejected must now succeed.
    ec2.delete_client_vpn_route(
        ClientVpnEndpointId=endpoint_id,
        DestinationCidrBlock=dest_cidr,
        TargetVpcSubnetId=subnet_id,
    )
    _poll_until(
        lambda: _route_status(ec2, endpoint_id, dest_cidr),
        lambda code: code is None,
        timeout_s=300,
        interval_s=5,
    )
    ec2.create_client_vpn_route(
        ClientVpnEndpointId=endpoint_id,
        DestinationCidrBlock=dest_cidr,
        TargetVpcSubnetId=subnet_id,
    )
    _poll_until(
        lambda: _route_status(ec2, endpoint_id, dest_cidr),
        lambda code: code in ("active", "pending"),
        timeout_s=120,
        interval_s=3,
    )
    restored_routes = ec2.describe_client_vpn_routes(
        ClientVpnEndpointId=endpoint_id,
        Filters=[{"Name": "destination-cidr", "Values": [dest_cidr]}],
    )["Routes"]
    assert len(restored_routes) == 1, (
        f"expected the identical route to be recreated after the conflict was removed, "
        f"found {len(restored_routes)}"
    )


# ===== helpers =====
def _create_client_vpn_endpoint_with_retry(ec2, timeout_s=240.0, interval_s=10.0, **kwargs):
    """CreateClientVpnEndpoint rejects with OperationNotPermitted ("Endpoint cannot be created
    while another endpoint is being created") when another creation is in flight elsewhere in
    the account/region. That is a transient account-wide contention window, not a real rejection
    of this request -- retry within a bounded window instead of failing outright.
    """
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return ec2.create_client_vpn_endpoint(**kwargs)
        except ClientError as exc:
            err = exc.response["Error"]
            if err["Code"] != "OperationNotPermitted" or "being created" not in err.get("Message", ""):
                raise
            if time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _error(fn):
    """(code, message) fn() raises; raises itself when the call succeeds."""
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
    raise AssertionError("the call succeeded; real AWS rejects it as a duplicate route")


def _route_status(ec2, endpoint_id, dest_cidr):
    routes = ec2.describe_client_vpn_routes(
        ClientVpnEndpointId=endpoint_id,
        Filters=[{"Name": "destination-cidr", "Values": [dest_cidr]}],
    )["Routes"]
    if not routes:
        return None
    return routes[0]["Status"]["Code"]


def _import_self_signed_cert(ctx) -> str:
    """Generate a throwaway self-signed X.509 cert/key and import it into ACM.

    Used as both the Client VPN server certificate and (mutual-auth) client root
    certificate chain -- neither needs to belong to a real CA hierarchy for the
    control-plane behavior under test (route creation), only to be importable and
    to carry a domain-shaped CN: CreateClientVpnEndpoint rejects a certificate with
    InvalidParameterValue ("does not have a domain") otherwise.
    """
    require_tools("openssl")
    acm = ctx.client("acm")
    with tempfile.TemporaryDirectory() as tmpdir:
        key_path = os.path.join(tmpdir, "key.pem")
        cert_path = os.path.join(tmpdir, "cert.pem")
        subprocess.run(
            [
                "openssl",
                "req",
                "-x509",
                "-newkey",
                "rsa:2048",
                "-keyout",
                key_path,
                "-out",
                cert_path,
                "-days",
                "2",
                "-nodes",
                "-subj",
                "/CN=sim2real-behavioral-test.example.com",
            ],
            check=True,
            capture_output=True,
            env=ctx.subprocess_env(),
        )
        with open(cert_path, "rb") as f:
            cert_bytes = f.read()
        with open(key_path, "rb") as f:
            key_bytes = f.read()

    cert_arn = acm.import_certificate(Certificate=cert_bytes, PrivateKey=key_bytes)[
        "CertificateArn"
    ]
    # The endpoint releases the certificate asynchronously after its own delete returns.
    ctx.on_cleanup(lambda: _retry_teardown(
        lambda: acm.delete_certificate(CertificateArn=cert_arn), ("ResourceInUseException",)
    ))
    return cert_arn


def _retry_teardown(fn, retry_codes, timeout_s=300.0, interval_s=15.0):
    """Teardown call: done on success or a not-found code; retry retry_codes until timeout_s,
    then re-raise so a leak is loud."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return fn()
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            if "NotFound" in code or code == "ResourceNotFoundException":
                return None
            if code not in retry_codes or time.monotonic() >= deadline:
                raise
        time.sleep(interval_s)


# EC2 network teardown waits for AWS-managed ENIs to leave before it deletes. A load balancer,
# directory, endpoint, cluster, function or instance in this VPC deletes ASYNCHRONOUSLY: its delete
# returns while its ENIs still sit in the subnet / security group, so an immediate DeleteSubnet /
# DeleteSecurityGroup / DeleteVpc fails with DependencyViolation, and swallowing that would leak the
# VPC while the check passes. So wait (bounded) for the resource's ENIs to go, retry
# DependencyViolation inside the same window, and raise a final failure naming the ENIs still
# attached. Every other error propagates.
# The window is shared by all of one check's network deletes and fits the suite's cleanup budget.
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
