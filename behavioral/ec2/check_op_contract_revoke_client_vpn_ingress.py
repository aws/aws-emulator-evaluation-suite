"""op-contract-revoke-client-vpn-ingress."""
from __future__ import annotations

import shutil
import subprocess
import tempfile
import time
from pathlib import Path

from behavioral_harness import tags

CHECK = "op-contract-revoke-client-vpn-ingress"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """AuthorizeClientVpnIngress followed by RevokeClientVpnIngress removes the ingress
    authorization rule for a target network CIDR, and revoking a CIDR that was never
    authorized on the endpoint is rejected with a distinct NotFound error."""
    from fidelity_tests_runner import require_tools

    require_tools("openssl")

    ec2 = ctx.client("ec2")
    acm = ctx.client("acm")

    server_cert_arn, ca_cert_arn = _import_self_signed_cert(ctx, acm)

    endpoint_id = ec2.create_client_vpn_endpoint(
        ClientCidrBlock="10.199.0.0/22",
        ServerCertificateArn=server_cert_arn,
        AuthenticationOptions=[
            {
                "Type": "certificate-authentication",
                "MutualAuthentication": {"ClientRootCertificateChainArn": ca_cert_arn},
            }
        ],
        ConnectionLogOptions={"Enabled": False},
        TagSpecifications=[
            {
                "ResourceType": "client-vpn-endpoint",
                "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-cvpn-")}],
            }
        ],
    )["ClientVpnEndpointId"]
    ctx.on_cleanup(lambda: ec2.delete_client_vpn_endpoint(ClientVpnEndpointId=endpoint_id))

    # A freshly created Client VPN endpoint remains in "pending-associate" indefinitely
    # until at least one target network (subnet) is associated with it -- that
    # association is what actually drives the transition to "available". Associate a
    # subnet before waiting for "available", otherwise the endpoint never leaves
    # "pending-associate".
    #
    # A Client VPN target network association only needs an existing subnet -- it does
    # not require a VPC created specifically for this check (the endpoint's
    # ClientCidrBlock is unrelated to the target subnet's own CIDR). Accounts have a
    # default VPC quota (5 per Region) that concurrently-running checks in this same
    # account/Region can already be close to, so creating yet another throwaway VPC
    # here has been observed to fail with VpcLimitExceeded. Prefer reusing an existing
    # subnet (the account's default VPC, if present) and only create a new VPC/subnet as
    # a fallback when no usable subnet already exists.
    subnet_id, vpc_id, owns_vpc = _find_or_create_target_subnet(ctx, ec2)

    association_id = ec2.associate_client_vpn_target_network(
        ClientVpnEndpointId=endpoint_id, SubnetId=subnet_id
    )["AssociationId"]
    ctx.on_cleanup(
        lambda: ec2.disassociate_client_vpn_target_network(
            ClientVpnEndpointId=endpoint_id, AssociationId=association_id
        )
    )

    # On real AWS, associating the first target network with a fresh Client VPN
    # endpoint provisions the underlying ENIs/routing and has been observed to take
    # well over five minutes -- a 300s bound is too tight and flakes with the
    # association still "associating". Use a longer bound consistent with the
    # endpoint-availability poll below.
    assert _poll_until(
        lambda: ec2.describe_client_vpn_target_networks(
            ClientVpnEndpointId=endpoint_id, AssociationIds=[association_id]
        )["ClientVpnTargetNetworks"][0]["Status"]["Code"],
        lambda status: status == "associated",
        timeout_s=900,
        interval_s=15,
    ) == "associated", "target network association never completed"

    # With the target network associated, the endpoint itself transitions to
    # "available"; authorization-rule mutations issued against a still-provisioning
    # endpoint appear to queue up behind that provisioning work, which made the
    # post-revoke "rule disappeared" transition take far longer (and less predictably)
    # than the analogous authorize-side transition. Waiting for the endpoint itself to
    # become available first keeps the subsequent authorize/revoke timing bounded.
    assert _poll_until(
        lambda: ec2.describe_client_vpn_endpoints(ClientVpnEndpointIds=[endpoint_id])[
            "ClientVpnEndpoints"
        ][0]["Status"]["Code"],
        lambda status: status == "available",
        timeout_s=300,
        interval_s=10,
    ) == "available", "Client VPN endpoint never became available"

    target_cidr = "10.222.0.0/24"
    ec2.authorize_client_vpn_ingress(
        ClientVpnEndpointId=endpoint_id,
        TargetNetworkCidr=target_cidr,
        AuthorizeAllGroups=True,
    )
    assert _poll_until(
        lambda: _rule_status(ec2, endpoint_id, target_cidr),
        lambda status: status == "active",
        timeout_s=90,
        interval_s=5,
    ), "authorization rule never became active"

    ec2.revoke_client_vpn_ingress(
        ClientVpnEndpointId=endpoint_id,
        TargetNetworkCidr=target_cidr,
        RevokeAllGroups=True,
    )
    # Revocation goes through a "revoking" transitional state, but on real AWS the rule
    # does not necessarily disappear from DescribeClientVpnAuthorizationRules once fully
    # revoked -- "revoked" is itself a documented terminal status code for an
    # authorization rule (authorizing | active | failed | revoking | revoked), and the
    # entry can remain listed with that status rather than being removed outright. Accept
    # either outcome (fully removed, or settled at the terminal "revoked" status) as
    # evidence the revoke completed, rather than requiring disappearance specifically.
    final_status = _poll_until(
        lambda: _rule_status(ec2, endpoint_id, target_cidr),
        lambda status: status is None or status == "revoked",
        timeout_s=600,
        interval_s=15,
    )
    assert final_status is None or final_status == "revoked", (
        f"authorization rule did not reach a revoked/removed state after "
        f"RevokeClientVpnIngress (status={final_status!r})"
    )

    err = _error(
        lambda: ec2.revoke_client_vpn_ingress(
            ClientVpnEndpointId=endpoint_id,
            TargetNetworkCidr="10.223.0.0/24",
            RevokeAllGroups=True,
        )
    )
    assert err["Code"] == "InvalidClientVpnEndpointAuthorizationRuleNotFound", (
        f"unexpected error: {err!r}"
    )
    assert err.get("Message") == "Specified rule does not exist or cannot be deleted", (
        f"unexpected message: {err.get('Message')!r}"
    )


# ===== helpers =====
def _error(fn):
    """Call fn(); return its ClientError Error dict. An unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]
    raise AssertionError(
        f"expected revoke_client_vpn_ingress on a never-authorized CIDR to be rejected, "
        f"but it succeeded and returned {result!r}"
    )


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    result = None
    while time.monotonic() < deadline:
        try:
            result = probe()
        except Exception:
            result = None
        if predicate(result):
            return result
        time.sleep(interval_s)
    return result if predicate(result) else False


def _find_or_create_target_subnet(ctx, ec2) -> tuple[str, str, bool]:
    """Returns (subnet_id, vpc_id, owns_vpc). Prefers an existing available subnet in
    the run's shared network (any Client VPN target network association just needs a
    subnet to attach to -- its CIDR is unrelated to the endpoint's ClientCidrBlock), to
    avoid contributing to the account's VPC quota. Falls back to creating a fresh
    VPC/subnet only if no usable default-VPC subnet is found."""
    default_vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])[
        "Vpcs"
    ]
    if default_vpcs:
        default_vpc_id = default_vpcs[0]["VpcId"]
        subnets = ec2.describe_subnets(
            Filters=[
                {"Name": "vpc-id", "Values": [default_vpc_id]},
                {"Name": "state", "Values": ["available"]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids},
            ]
        )["Subnets"]
        if subnets:
            return subnets[0]["SubnetId"], default_vpc_id, False

    vpc_id = ec2.create_vpc(CidrBlock="10.198.0.0/16")["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc_id))
    ec2.get_waiter("vpc_available").wait(VpcIds=[vpc_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})

    subnet_id = ec2.create_subnet(VpcId=vpc_id, CidrBlock="10.198.1.0/24")["Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_subnet", SubnetId=subnet_id))

    return subnet_id, vpc_id, True


def _rule_status(ec2, endpoint_id: str, target_cidr: str):
    resp = ec2.describe_client_vpn_authorization_rules(ClientVpnEndpointId=endpoint_id)
    for rule in resp.get("AuthorizationRules", []):
        if rule.get("DestinationCidr") == target_cidr:
            return rule.get("Status", {}).get("Code")
    return None


def _import_self_signed_cert(ctx, acm) -> tuple[str, str]:
    """Builds a minimal CA certificate plus a leaf server certificate signed by that CA
    (via the openssl CLI) and imports both into ACM. Returns (server_cert_arn, ca_cert_arn).

    Client VPN's mutual-auth model expects two distinct roles: a leaf server certificate
    presented by the endpoint (ServerCertificateArn), and a separate CA certificate used
    as the client root trust anchor (ClientRootCertificateChainArn). Reusing a single
    self-signed CA:TRUE certificate for both roles -- i.e. presenting a CA certificate as
    the server's leaf certificate -- is rejected by CreateClientVpnEndpoint with
    InvalidParameterValue on the server certificate.
    """
    tmp_dir = Path(tempfile.mkdtemp(prefix="sim2real-cvpn-"))
    ctx.on_cleanup(lambda: shutil.rmtree(tmp_dir, ignore_errors=True))
    env = ctx.subprocess_env()

    ca_key = tmp_dir / "ca-key.pem"
    ca_cert = tmp_dir / "ca-cert.pem"
    server_key = tmp_dir / "server-key.pem"
    server_csr = tmp_dir / "server-csr.pem"
    server_cert = tmp_dir / "server-cert.pem"
    ext_file = tmp_dir / "server-ext.cnf"

    # Self-signed root CA -- used only as the client root certificate chain trust anchor,
    # never presented as a server certificate.
    subprocess.run(
        [
            "openssl",
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-keyout",
            str(ca_key),
            "-out",
            str(ca_cert),
            "-days",
            "1",
            "-nodes",
            "-subj",
            "/CN=sim2real-behavioral-ca",
            "-addext",
            "basicConstraints=critical,CA:TRUE",
            "-addext",
            "keyUsage=critical,keyCertSign,cRLSign",
        ],
        check=True,
        capture_output=True,
        env=env,
    )

    # Leaf server certificate, signed by the CA above (explicitly not a CA itself, and
    # scoped to TLS server use).
    subprocess.run(
        [
            "openssl",
            "req",
            "-newkey",
            "rsa:2048",
            "-keyout",
            str(server_key),
            "-out",
            str(server_csr),
            "-nodes",
            "-subj",
            "/CN=sim2real-behavioral-server",
        ],
        check=True,
        capture_output=True,
        env=env,
    )
    ext_file.write_text(
        "basicConstraints=CA:FALSE\n"
        "keyUsage=digitalSignature,keyEncipherment\n"
        "extendedKeyUsage=serverAuth\n"
        "subjectAltName=DNS:sim2real-behavioral-server\n"
    )
    subprocess.run(
        [
            "openssl",
            "x509",
            "-req",
            "-in",
            str(server_csr),
            "-CA",
            str(ca_cert),
            "-CAkey",
            str(ca_key),
            "-CAcreateserial",
            "-out",
            str(server_cert),
            "-days",
            "1",
            "-extfile",
            str(ext_file),
        ],
        check=True,
        capture_output=True,
        env=env,
    )

    ca_cert_arn = acm.import_certificate(
        Certificate=ca_cert.read_bytes(), PrivateKey=ca_key.read_bytes()
    )["CertificateArn"]
    ctx.on_cleanup(lambda: acm.delete_certificate(CertificateArn=ca_cert_arn))

    server_cert_arn = acm.import_certificate(
        Certificate=server_cert.read_bytes(),
        PrivateKey=server_key.read_bytes(),
        CertificateChain=ca_cert.read_bytes(),
    )["CertificateArn"]
    ctx.on_cleanup(lambda: acm.delete_certificate(CertificateArn=server_cert_arn))

    return server_cert_arn, ca_cert_arn


# Network teardown: an async delete's AWS-managed ENIs hold the subnet / security group / VPC in
# DependencyViolation, so wait for them to go and retry DependencyViolation to one deadline shared by
# all of a check's network deletes (within the suite cleanup budget), then raise naming the ENIs left.
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
