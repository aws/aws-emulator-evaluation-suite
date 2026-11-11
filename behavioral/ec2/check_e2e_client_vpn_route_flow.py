"""e2e-client-vpn-route-flow."""
from __future__ import annotations

import datetime
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "e2e-client-vpn-route-flow"
GROUP = "e2e"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateClientVpnRoute adds a route that shows in DescribeClientVpnRoutes; DeleteClientVpnRoute
    removes it and the table converges back to the automatic route for the associated subnet."""
    ec2 = ctx.client("ec2")
    acm = ctx.client("acm")

    server_cert_pem, server_key = _self_signed_cert(ctx, "server")
    server_arn = acm.import_certificate(
        Certificate=server_cert_pem, PrivateKey=server_key
    )["CertificateArn"]
    ctx.on_cleanup(lambda: _safe(lambda: acm.delete_certificate(CertificateArn=server_arn)))

    ca_cert_pem, ca_key = _self_signed_cert(ctx, "ca")
    ca_arn = acm.import_certificate(Certificate=ca_cert_pem, PrivateKey=ca_key)[
        "CertificateArn"
    ]
    ctx.on_cleanup(lambda: _safe(lambda: acm.delete_certificate(CertificateArn=ca_arn)))

    az = ec2.describe_availability_zones(
        Filters=[{"Name": "state", "Values": ["available"]}]
    )["AvailabilityZones"][0]["ZoneName"]
    vpc_id = ec2.create_vpc(CidrBlock="10.242.0.0/16")["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _safe(lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc_id)))
    subnet_id = ec2.create_subnet(
        VpcId=vpc_id, CidrBlock="10.242.1.0/24", AvailabilityZone=az
    )["Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda: _safe(lambda: _delete_net(ec2, "delete_subnet", SubnetId=subnet_id)))

    endpoint = ec2.create_client_vpn_endpoint(
        ClientCidrBlock="10.243.0.0/22",
        ServerCertificateArn=server_arn,
        AuthenticationOptions=[
            {"Type": "certificate-authentication", "MutualAuthentication": {"ClientRootCertificateChainArn": ca_arn}}
        ],
        ConnectionLogOptions={"Enabled": False},
        VpcId=vpc_id,
        TagSpecifications=[
            {
                "ResourceType": "client-vpn-endpoint",
                "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-cvpn-")}],
            }
        ],
    )
    endpoint_id = endpoint["ClientVpnEndpointId"]
    ctx.on_cleanup(
        lambda: _safe(lambda: ec2.delete_client_vpn_endpoint(ClientVpnEndpointId=endpoint_id))
    )
    # A freshly created Client VPN endpoint never transitions to "available" on its
    # own -- it legitimately stays "pending-associate" until a target network is
    # associated with it. Wait only for a state association can be initiated from.
    _poll_until(
        lambda: ec2.describe_client_vpn_endpoints(ClientVpnEndpointIds=[endpoint_id])[
            "ClientVpnEndpoints"
        ][0]["Status"]["Code"],
        lambda code: code in ("pending-associate", "available"),
        timeout_s=300,
        interval_s=10.0,
    )

    assoc = ec2.associate_client_vpn_target_network(
        ClientVpnEndpointId=endpoint_id, SubnetId=subnet_id
    )
    assoc_id = assoc["AssociationId"]
    ctx.on_cleanup(
        lambda: _safe(
            lambda: ec2.disassociate_client_vpn_target_network(
                ClientVpnEndpointId=endpoint_id, AssociationId=assoc_id
            )
        )
    )
    _poll_until(
        lambda: ec2.describe_client_vpn_target_networks(
            ClientVpnEndpointId=endpoint_id, AssociationIds=[assoc_id]
        )["ClientVpnTargetNetworks"][0]["Status"]["Code"],
        lambda code: code == "associated",
        timeout_s=900,
        interval_s=15.0,
    )

    def _find_route(cidr):
        routes = ec2.describe_client_vpn_routes(ClientVpnEndpointId=endpoint_id)["Routes"]
        return next((r for r in routes if r["DestinationCidr"] == cidr), None)

    # The subnet association auto-creates a 'local' VPC route -- confirm the
    # baseline before adding our own manually-created route.
    local_route = _poll_until(
        lambda: _find_route("10.242.0.0/16"), lambda r: r is not None, timeout_s=60
    )
    assert local_route["Origin"] == "associate"

    dest_cidr = "10.222.0.0/16"
    ec2.create_client_vpn_route(
        ClientVpnEndpointId=endpoint_id,
        DestinationCidrBlock=dest_cidr,
        TargetVpcSubnetId=subnet_id,
        Description=ctx.unique_name("sim2real-cvpn-route-"),
    )

    added = _poll_until(
        lambda: _find_route(dest_cidr), lambda r: r is not None, timeout_s=120
    )
    assert added["Origin"] == "add-route"
    assert added["TargetSubnet"] == subnet_id
    added = _poll_until(
        lambda: _find_route(dest_cidr), lambda r: r is not None and r["Status"]["Code"] == "active", timeout_s=120
    )
    assert added["Status"]["Code"] == "active"

    ec2.delete_client_vpn_route(
        ClientVpnEndpointId=endpoint_id,
        TargetVpcSubnetId=subnet_id,
        DestinationCidrBlock=dest_cidr,
    )
    gone = _poll_until(lambda: _find_route(dest_cidr), lambda r: r is None, timeout_s=120)
    assert gone is None

    # The route table converges back to just the automatic local route.
    remaining = ec2.describe_client_vpn_routes(ClientVpnEndpointId=endpoint_id)["Routes"]
    assert all(r["DestinationCidr"] != dest_cidr for r in remaining)
    assert any(r["DestinationCidr"] == "10.242.0.0/16" for r in remaining)


# ===== helpers (self-contained) =====
def _safe(fn) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "InvalidClientVpnEndpointId.NotFound",
            "InvalidNetworkInterfaceID.NotFound",
            "ResourceNotFoundException",
        ):
            raise


def _self_signed_cert(ctx, cn_prefix: str):
    """Generate a minimal self-signed RSA certificate/key PEM pair -- ACM
    accepts a self-signed cert for Client VPN's mutual-auth requirements."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    domain = f"{ctx.unique_name(f'sim2real-{cn_prefix}-')}.example.com"
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, domain)])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=30))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(domain)]), critical=False)
        .sign(key, hashes.SHA256())
    )
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    key_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )
    return cert_pem, key_pem


def _poll_until(probe, predicate, timeout_s=120.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s, last={last!r}")


# AWS-managed ENIs in this VPC delete asynchronously, so DeleteSubnet / DeleteSecurityGroup /
# DeleteVpc fail DependencyViolation while they remain: retry that code inside one window shared
# by the network deletes, then raise naming the ENIs still attached.
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
        _time.sleep(2)
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
        _time.sleep(2)


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
