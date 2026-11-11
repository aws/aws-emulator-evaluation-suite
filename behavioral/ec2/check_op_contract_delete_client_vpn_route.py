"""op-contract-deleteClientVpnRoute."""
from __future__ import annotations

import os
import subprocess
import tempfile
import time

from behavioral_harness import tags

CHECK = "op-contract-deleteClientVpnRoute"
GROUP = "error-semantics"
SERVICES = ["ec2"]

_DRY_RUN_MESSAGE = "Request would have succeeded, but DryRun flag is set."


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeleteClientVpnRoute: success removes a static route added over an associated target
    network; a nonexistent ClientVpnEndpointId is rejected."""
    ec2 = ctx.client("ec2")
    acm = ctx.client("acm")

    azs = ec2.describe_availability_zones(
        Filters=[{"Name": "state", "Values": ["available"]}]
    )["AvailabilityZones"]
    az = azs[0]["ZoneName"]

    vpc_id = _create_vpc(ec2, "10.224.0.0/16")
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc_id))
    ec2.create_tags(Resources=[vpc_id], Tags=[{"Key": "sim2real", "Value": "1"}])
    subnet_id = ec2.create_subnet(
        VpcId=vpc_id,
        CidrBlock="10.224.1.0/24",
        AvailabilityZone=az,
        TagSpecifications=[{"ResourceType": "subnet", "Tags": [{"Key": "sim2real", "Value": "1"}]}],
    )["Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_subnet", SubnetId=subnet_id))
    sg_id = ec2.create_security_group(
        VpcId=vpc_id,
        GroupName=ctx.unique_name("sim2real-cvpn-rt-sg-"),
        Description="sim2real",
        TagSpecifications=[{"ResourceType": "security-group", "Tags": [{"Key": "sim2real", "Value": "1"}]}],
    )["GroupId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_security_group", GroupId=sg_id))

    cert_pem, key_pem = _self_signed_cert_pem()
    cert_arn = acm.import_certificate(Certificate=cert_pem, PrivateKey=key_pem)["CertificateArn"]
    # The endpoint releases the certificate asynchronously after its own delete returns.
    ctx.on_cleanup(lambda: _retry_teardown(
        lambda: acm.delete_certificate(CertificateArn=cert_arn), ("ResourceInUseException",)
    ))

    endpoint_id = _create_client_vpn_endpoint_with_retry(
        ec2,
        ClientCidrBlock="10.98.0.0/22",
        ServerCertificateArn=cert_arn,
        AuthenticationOptions=[
            {
                "Type": "certificate-authentication",
                "MutualAuthentication": {"ClientRootCertificateChainArn": cert_arn},
            }
        ],
        ConnectionLogOptions={"Enabled": False},
        Description=ctx.unique_name("sim2real-cvpn-rt-"),
        TagSpecifications=[
            {"ResourceType": "client-vpn-endpoint", "Tags": [{"Key": "sim2real", "Value": "1"}]}
        ],
    )["ClientVpnEndpointId"]
    ctx.on_cleanup(lambda: _retry_teardown(
        lambda: ec2.delete_client_vpn_endpoint(ClientVpnEndpointId=endpoint_id),
        ("IncorrectState", "InvalidClientVpnEndpointState", "InvalidState"),
    ))
    ec2.apply_security_groups_to_client_vpn_target_network(
        ClientVpnEndpointId=endpoint_id, VpcId=vpc_id, SecurityGroupIds=[sg_id]
    )

    assoc_id = ec2.associate_client_vpn_target_network(
        ClientVpnEndpointId=endpoint_id, SubnetId=subnet_id
    )["AssociationId"]
    # An endpoint with a target network still associated cannot be deleted, so disassociate first.
    ctx.on_cleanup(lambda: _retry_teardown(
        lambda: ec2.disassociate_client_vpn_target_network(
            ClientVpnEndpointId=endpoint_id, AssociationId=assoc_id
        ),
        ("IncorrectState", "InvalidClientVpnAssociationIdState", "InvalidState"),
    ))

    def _probe():
        assocs = ec2.describe_client_vpn_target_networks(
            ClientVpnEndpointId=endpoint_id, AssociationIds=[assoc_id]
        )["ClientVpnTargetNetworks"]
        return assocs[0]["Status"]["Code"] if assocs else "unknown"

    state = _poll_until(_probe, lambda s: s in ("associated", "association-failed"), timeout_s=600, interval_s=10)
    if state != "associated":
        raise AssertionError(
            f"target network association did not reach 'associated' in time (state={state!r})",
        )

    destination = "10.50.0.0/24"
    ec2.create_client_vpn_route(
        ClientVpnEndpointId=endpoint_id,
        DestinationCidrBlock=destination,
        TargetVpcSubnetId=subnet_id,
    )

    def _route_probe():
        routes = ec2.describe_client_vpn_routes(
            ClientVpnEndpointId=endpoint_id,
            Filters=[{"Name": "destination-cidr", "Values": [destination]}],
        )["Routes"]
        return routes[0]["Status"]["Code"] if routes else "gone"

    route_state = _poll_until(_route_probe, lambda s: s in ("active", "gone"), timeout_s=120, interval_s=5)
    if route_state != "active":
        raise AssertionError(
            f"client VPN route never reached 'active' (state={route_state!r})",
        )

    # Error boundary: DryRun must short-circuit before the delete is applied.
    err = _client_error(
        lambda: ec2.delete_client_vpn_route(
            ClientVpnEndpointId=endpoint_id,
            DestinationCidrBlock=destination,
            TargetVpcSubnetId=subnet_id,
            DryRun=True,
        )
    )
    assert err.get("Code") == "DryRunOperation", f"expected DryRunOperation, got {err!r}"
    assert err.get("Message") == _DRY_RUN_MESSAGE, f"unexpected DryRun message: {err!r}"
    unaffected_state = _route_probe()
    assert unaffected_state == "active", (
        f"DryRun must not mutate state, but the route is now {unaffected_state!r}"
    )

    ec2.delete_client_vpn_route(
        ClientVpnEndpointId=endpoint_id,
        DestinationCidrBlock=destination,
        TargetVpcSubnetId=subnet_id,
    )

    final_state = _poll_until(_route_probe, lambda s: s == "gone", timeout_s=300, interval_s=10)
    assert final_state == "gone", f"expected the route to be removed, still {final_state!r}"

    # Error boundary: a nonexistent ClientVpnEndpointId is rejected.
    err2 = _client_error(
        lambda: ec2.delete_client_vpn_route(
            ClientVpnEndpointId="cvpn-endpoint-00000000000000000",
            DestinationCidrBlock=destination,
        )
    )
    assert err2.get("Code") == "InvalidClientVpnEndpointId.NotFound", f"expected InvalidClientVpnEndpointId.NotFound, got {err2!r}"
    assert err2.get("Message") == "Endpoint cvpn-endpoint-00000000000000000 does not exist", (
        f"unexpected not-found message: {err2!r}"
    )


# ===== helpers =====
def _client_error(fn):
    """Call fn(); return its botocore Error dict. An unexpected success raises AssertionError."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")


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


def _create_vpc(ec2, cidr_block):
    """Create a VPC, failing loudly if the account has no quota left.

    A quota exhaustion is an environment precondition, not something a check may fix by deleting
    resources it does not own, so `VpcLimitExceeded` propagates.
    """
    return ec2.create_vpc(CidrBlock=cidr_block)["Vpc"]["VpcId"]


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    return last


def _self_signed_cert_pem() -> tuple[bytes, bytes]:
    """Generate a throwaway self-signed cert/key pair via the openssl CLI (no external deps)."""
    from fidelity_tests_runner import require_tools

    require_tools("openssl")
    with tempfile.TemporaryDirectory() as d:
        key_path = os.path.join(d, "key.pem")
        cert_path = os.path.join(d, "cert.pem")
        try:
            subprocess.run(
                [
                    "openssl", "req", "-x509", "-nodes", "-newkey", "rsa:2048",
                    "-keyout", key_path, "-out", cert_path, "-days", "2",
                    "-subj", "/CN=sim2real-cvpn-route.example.com",
                    "-addext", "basicConstraints=critical,CA:true",
                    "-addext", "keyUsage=critical,keyCertSign,cRLSign,digitalSignature",
                ],
                check=True,
                capture_output=True,
                timeout=30,
            )
        except (subprocess.CalledProcessError, OSError) as exc:
            raise AssertionError(f"unable to generate a self-signed test certificate: {exc}") from exc
        with open(key_path, "rb") as f:
            key_pem = f.read()
        with open(cert_path, "rb") as f:
            cert_pem = f.read()
    return cert_pem, key_pem


# EC2 network teardown waits for AWS-managed ENIs to leave before it deletes. A load balancer,
# directory, endpoint, cluster, function or instance in this VPC deletes ASYNCHRONOUSLY: its delete
# returns while its ENIs still sit in the subnet / security group, so an immediate DeleteSubnet /
# DeleteSecurityGroup / DeleteVpc fails with DependencyViolation. Wait (bounded) for the resource's
# ENIs to go, retry DependencyViolation inside the same window, and raise a final failure naming the
# ENIs still attached. Every other error propagates. Teardown-only: nothing run() executes calls
# this, so it cannot change the verdict. The window is shared by all of one check's network deletes.
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
