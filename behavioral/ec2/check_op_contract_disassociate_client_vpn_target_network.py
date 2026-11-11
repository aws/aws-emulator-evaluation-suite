"""op-contract-disassociate-client-vpn-target-network."""
from __future__ import annotations

import subprocess
import tempfile
import time
from pathlib import Path

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-disassociate-client-vpn-target-network"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DisassociateClientVpnTargetNetwork with DryRun answers DryRunOperation and keeps the association;
    the real call removes the endpoint's last association, which returns it to pending-associate, and a
    repeat fails with InvalidClientVpnAssociationIdNotFound (exact messages)."""
    from fidelity_tests_runner import require_tools

    require_tools("openssl")
    ec2 = ctx.client("ec2")
    acm = ctx.client("acm")

    server_cert_arn = _import_self_signed_cert(ctx, acm, "server")
    ca_cert_arn = _import_self_signed_cert(ctx, acm, "ca")

    vpc_id, subnet_id = _pick_default_vpc_and_subnet(ec2, ctx=ctx)
    name_tag = ctx.unique_name("sim2real-cvpn-")
    if vpc_id is None:
        vpc_id = _create_with_retry(
            lambda: ec2.create_vpc(
                CidrBlock="10.90.0.0/16",
                TagSpecifications=[{"ResourceType": "vpc", "Tags": [{"Key": "Name", "Value": name_tag}]}],
            )["Vpc"]["VpcId"],
            retry_codes=("VpcLimitExceeded",),
            timeout_s=300.0,
            interval_s=15.0,
        )
        ctx.on_cleanup(lambda: _safe(lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc_id)))
    if subnet_id is None:
        az = ec2.describe_availability_zones()["AvailabilityZones"][0]["ZoneName"]
        subnet_id = ec2.create_subnet(
            VpcId=vpc_id,
            CidrBlock="10.90.1.0/24",
            AvailabilityZone=az,
            TagSpecifications=[{"ResourceType": "subnet", "Tags": [{"Key": "Name", "Value": name_tag}]}],
        )["Subnet"]["SubnetId"]
        ctx.on_cleanup(lambda: _safe(lambda: _delete_net(ec2, "delete_subnet", SubnetId=subnet_id)))

    cvpn_id = ec2.create_client_vpn_endpoint(
        ClientCidrBlock="10.91.0.0/22",
        ServerCertificateArn=server_cert_arn,
        AuthenticationOptions=[
            {
                "Type": "certificate-authentication",
                "MutualAuthentication": {"ClientRootCertificateChainArn": ca_cert_arn},
            }
        ],
        ConnectionLogOptions={"Enabled": False},
        TransportProtocol="udp",
        Description=name_tag,
        TagSpecifications=[{"ResourceType": "client-vpn-endpoint", "Tags": [{"Key": "Name", "Value": name_tag}]}],
    )["ClientVpnEndpointId"]
    ctx.on_cleanup(lambda: _teardown_client_vpn_endpoint(ec2, cvpn_id))

    # A new Client VPN endpoint stays pending-associate until it has a target-network association, so
    # wait for pending-associate (or available) before AssociateClientVpnTargetNetwork.
    _poll_until(
        lambda: ec2.describe_client_vpn_endpoints(ClientVpnEndpointIds=[cvpn_id])["ClientVpnEndpoints"][0][
            "Status"
        ]["Code"],
        lambda code: code in ("pending-associate", "available"),
        timeout_s=300.0,
        interval_s=10.0,
    )

    assoc_id = ec2.associate_client_vpn_target_network(ClientVpnEndpointId=cvpn_id, SubnetId=subnet_id)[
        "AssociationId"
    ]

    def _assoc_status():
        assocs = ec2.describe_client_vpn_target_networks(
            ClientVpnEndpointId=cvpn_id, AssociationIds=[assoc_id]
        )["ClientVpnTargetNetworks"]
        return assocs[0]["Status"]["Code"] if assocs else None

    # The first target-network association can take over four minutes while the endpoint builds its
    # association infrastructure, so this poll has a longer bound.
    _poll_until(_assoc_status, lambda code: code == "associated", timeout_s=600.0, interval_s=15.0)

    # Error boundary: DryRun must report DryRunOperation without disassociating.
    code, message = _client_error(
        lambda: ec2.disassociate_client_vpn_target_network(
            ClientVpnEndpointId=cvpn_id, AssociationId=assoc_id, DryRun=True
        )
    )
    assert code == "DryRunOperation", code
    assert message == "Request would have succeeded, but DryRun flag is set.", (
        f"unexpected DryRunOperation message: {message!r}"
    )
    status_after_dryrun = _assoc_status()
    assert status_after_dryrun == "associated", status_after_dryrun

    resp = ec2.disassociate_client_vpn_target_network(ClientVpnEndpointId=cvpn_id, AssociationId=assoc_id)
    assert resp["AssociationId"] == assoc_id, resp

    # Removing the last target-network association can also take over three minutes, so this poll uses
    # the same longer bound as the associate side.
    _poll_until(_assoc_status, lambda code: code in (None, "disassociated"), timeout_s=600.0, interval_s=15.0)

    # The association has now fully cleared (terminal "disassociated" or already
    # absent from describe) -- repeating the disassociate on that id must fail,
    # not silently repeat the same success.
    repeat_code, repeat_message = _client_error(
        lambda: ec2.disassociate_client_vpn_target_network(ClientVpnEndpointId=cvpn_id, AssociationId=assoc_id)
    )
    assert repeat_code == "InvalidClientVpnAssociationIdNotFound", (
        f"expected disassociating an already-gone association id to be rejected, got {repeat_code}"
    )
    assert repeat_message == "Association is not found", (
        f"unexpected InvalidClientVpnAssociationIdNotFound message: {repeat_message!r}"
    )

    # This was the only target network association: the endpoint should fall
    # back to pending-associate once it fully clears.
    _poll_until(
        lambda: ec2.describe_client_vpn_endpoints(ClientVpnEndpointIds=[cvpn_id])["ClientVpnEndpoints"][0][
            "Status"
        ]["Code"],
        lambda code: code == "pending-associate",
        timeout_s=300.0,
        interval_s=10.0,
    )


# ===== helpers =====
def _pick_default_vpc_and_subnet(ec2, *, ctx):
    """Prefer the account's existing shared network (and one of its
    already-provisioned subnets) over allocating a brand-new VPC — the
    shared network costs nothing against the per-account VPC limit and already
    has a usable subnet for the Client VPN target-network association."""
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        return None, None
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(
        Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "state", "Values": ["available"]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}]
    )["Subnets"]
    if not subnets:
        return vpc_id, None
    subnet = max(subnets, key=lambda s: s.get("AvailableIpAddressCount", 0))
    return vpc_id, subnet["SubnetId"]


def _create_with_retry(fn, retry_codes, timeout_s=300.0, interval_s=15.0):
    """Retry a create call on the given transient limit codes (VpcLimitExceeded can take minutes to clear
    while concurrent checks hold VPCs) until timeout_s, leaving most of the check budget for the slow
    Client VPN provisioning; re-raise any other error."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return fn()
        except ClientError as e:
            if e.response["Error"]["Code"] in retry_codes and time.monotonic() < deadline:
                time.sleep(interval_s)
                continue
            raise


def _import_self_signed_cert(ctx, acm, tag: str) -> str:
    with tempfile.TemporaryDirectory() as tmp:
        key_path = Path(tmp) / f"{tag}.key"
        crt_path = Path(tmp) / f"{tag}.crt"
        cn = ctx.unique_name(f"sim2real-{tag}-")
        if tag == "ca":
            # ClientRootCertificateChainArn must be a CA certificate: a self-signed end-entity certificate
            # fails CreateClientVpnEndpoint with InvalidParameterValue, so mark it CA:true with CA key usage.
            extra_args = [
                "-addext", "basicConstraints=critical,CA:true",
                "-addext", "keyUsage=critical,keyCertSign,cRLSign",
                "-addext", f"subjectAltName=DNS:{cn}",
            ]
        else:
            # ServerCertificateArn must be a TLS server certificate with a Subject Alternative Name: one with
            # only a Subject CN fails CreateClientVpnEndpoint with InvalidParameterValue.
            extra_args = [
                "-addext", "keyUsage=critical,digitalSignature,keyEncipherment",
                "-addext", "extendedKeyUsage=critical,serverAuth",
                "-addext", f"subjectAltName=DNS:{cn}",
            ]
        subprocess.run(
            [
                "openssl", "req", "-x509", "-newkey", "rsa:2048",
                "-keyout", str(key_path), "-out", str(crt_path),
                "-days", "2", "-nodes", "-subj", f"/CN={cn}",
                *extra_args,
            ],
            check=True,
            capture_output=True,
        )
        cert_arn = acm.import_certificate(
            Certificate=crt_path.read_bytes(),
            PrivateKey=key_path.read_bytes(),
            Tags=[{"Key": "Name", "Value": cn}],
        )["CertificateArn"]
        ctx.on_cleanup(lambda: _delete_certificate(acm, cert_arn))
        return cert_arn


# Client VPN deletes are asynchronous: DeleteClientVpnEndpoint is refused while a target network is
# associated, and ACM refuses a certificate delete (ResourceInUseException) until the endpoint is
# gone, so the teardown disassociates, waits, deletes, waits, and retries the certificate delete.
_CVPN_TEARDOWN_S = 600.0


def _cvpn_live_associations(ec2, cvpn_id):
    from botocore.exceptions import ClientError

    try:
        nets = ec2.describe_client_vpn_target_networks(ClientVpnEndpointId=cvpn_id)["ClientVpnTargetNetworks"]
    except ClientError:
        return []
    return [n for n in nets if n.get("Status", {}).get("Code") != "disassociated"]


def _cvpn_exists(ec2, cvpn_id):
    from botocore.exceptions import ClientError

    try:
        eps = ec2.describe_client_vpn_endpoints(ClientVpnEndpointIds=[cvpn_id])["ClientVpnEndpoints"]
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "InvalidClientVpnEndpointId.NotFound":
            raise
        return False
    return any(e.get("Status", {}).get("Code") != "deleted" for e in eps)


def _teardown_client_vpn_endpoint(ec2, cvpn_id: str) -> None:
    deadline = time.monotonic() + _CVPN_TEARDOWN_S
    for net in _cvpn_live_associations(ec2, cvpn_id):
        if net.get("Status", {}).get("Code") != "disassociating":
            _safe(lambda n=net: ec2.disassociate_client_vpn_target_network(
                ClientVpnEndpointId=cvpn_id, AssociationId=n["AssociationId"]
            ))
    while _cvpn_live_associations(ec2, cvpn_id) and time.monotonic() < deadline:
        time.sleep(15)
    _safe(lambda: ec2.delete_client_vpn_endpoint(ClientVpnEndpointId=cvpn_id))
    while _cvpn_exists(ec2, cvpn_id) and time.monotonic() < deadline:
        time.sleep(15)
    if _cvpn_exists(ec2, cvpn_id):
        raise RuntimeError(
            f"client vpn endpoint {cvpn_id} still present after {_CVPN_TEARDOWN_S}s"
        )


def _delete_certificate(acm, cert_arn: str, timeout_s: float = 300.0) -> None:
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            acm.delete_certificate(CertificateArn=cert_arn)
            return
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            if code == "ResourceNotFoundException":
                return
            if code != "ResourceInUseException" or time.monotonic() >= deadline:
                raise RuntimeError(f"delete_certificate: {code}") from exc
        time.sleep(15)


def _client_error(fn):
    """Call fn(); return its error (code, message). An unexpected SUCCESS raises, because a
    target ACCEPTING a call real AWS refuses must not read as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _poll_until(probe, predicate, timeout_s=120.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last}")


def _safe(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "InvalidClientVpnEndpointId.NotFound",
            "InvalidNetworkInterfaceID.NotFound",
        ):
            raise


# EC2 network deletes wait for AWS-managed ENIs to leave: a resource in this VPC deletes asynchronously,
# so DeleteSubnet/DeleteSecurityGroup/DeleteVpc fail with DependencyViolation until its ENIs go. Retry
# that code to one deadline shared by the check's network deletes, then raise naming the ENIs left.
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
