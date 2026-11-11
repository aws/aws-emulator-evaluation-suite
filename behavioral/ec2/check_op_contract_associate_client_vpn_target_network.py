"""op-contract-associate-client-vpn-target-network."""
from __future__ import annotations

import subprocess
import tempfile
import time
from pathlib import Path

from behavioral_harness import tags

CHECK = "op-contract-associate-client-vpn-target-network"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """AssociateClientVpnTargetNetwork attaches a subnet to a Client VPN endpoint; a bogus
    endpoint id is rejected (InvalidClientVpnEndpointId.NotFound)."""
    from fidelity_tests_runner import require_tools

    require_tools("openssl")

    ec2 = ctx.client("ec2")
    acm = ctx.client("acm")
    vpc_id, subnet_id = _default_vpc_subnet(ctx)
    cert_arn = _self_signed_acm_cert(ctx, acm)

    endpoint_id = ec2.create_client_vpn_endpoint(
        ClientCidrBlock="10.199.0.0/22",
        ServerCertificateArn=cert_arn,
        AuthenticationOptions=[
            {"Type": "certificate-authentication", "MutualAuthentication": {"ClientRootCertificateChainArn": cert_arn}}
        ],
        ConnectionLogOptions={"Enabled": False},
        TagSpecifications=[
            {"ResourceType": "client-vpn-endpoint", "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-cvpn-")}]}
        ],
    )["ClientVpnEndpointId"]
    ctx.on_cleanup(lambda: ec2.delete_client_vpn_endpoint(ClientVpnEndpointId=endpoint_id))

    # A freshly created Client VPN endpoint's status legitimately stays "pending-associate"
    # (not "available") until at least one target network is associated with it -- AWS never
    # transitions it to "available" on its own, so waiting for "available" here would spin
    # until timeout. Just confirm the endpoint is in one of the states from which an
    # association can be initiated before proceeding.
    endpoint_status = _poll_until(
        lambda: ec2.describe_client_vpn_endpoints(ClientVpnEndpointIds=[endpoint_id])["ClientVpnEndpoints"][0][
            "Status"
        ]["Code"],
        lambda code: code in ("pending-associate", "available"),
        timeout_s=300,
        interval_s=10,
    )
    assert endpoint_status in ("pending-associate", "available"), endpoint_status

    assoc = ec2.associate_client_vpn_target_network(ClientVpnEndpointId=endpoint_id, SubnetId=subnet_id)
    assoc_id = assoc["AssociationId"]
    ctx.on_cleanup(
        lambda: ec2.disassociate_client_vpn_target_network(ClientVpnEndpointId=endpoint_id, AssociationId=assoc_id)
    )

    final_status = _poll_until(
        lambda: ec2.describe_client_vpn_target_networks(ClientVpnEndpointId=endpoint_id, AssociationIds=[assoc_id])[
            "ClientVpnTargetNetworks"
        ][0]["Status"]["Code"],
        lambda code: code in ("associated", "association-failed"),
        timeout_s=900,
        interval_s=15,
    )
    assert final_status == "associated", f"association ended in state {final_status}"

    fake_endpoint_id = "cvpn-endpoint-0000000000000000f"
    code, message = _client_error(
        lambda: ec2.associate_client_vpn_target_network(
            ClientVpnEndpointId=fake_endpoint_id, SubnetId=subnet_id
        )
    )
    assert code == "InvalidClientVpnEndpointId.NotFound", f"unexpected error code: {code}"
    expected = f"Endpoint {fake_endpoint_id} does not exist"
    assert message == expected, f"expected message {expected!r}, got {message!r}"


def _client_error(fn):
    """Call fn(); return its (code, message). An unexpected SUCCESS raises, because a target
    ACCEPTING a call real AWS refuses must not read as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s, last value: {last}")


def _default_vpc_subnet(ctx):
    # Reuse the run's shared network/subnet instead of creating a dedicated VPC: accounts
    # have a small per-region VPC quota and a Client VPN target-network association doesn't
    # need a bespoke network, just an existing subnet to attach to.
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError("no shared network VPC available in this account/region")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    if not subnets:
        raise AssertionError("shared network has no subnets")
    return vpc_id, subnets[0]["SubnetId"]


def _self_signed_acm_cert(ctx, acm) -> str:
    with tempfile.TemporaryDirectory() as tmp:
        key_path = Path(tmp) / "key.pem"
        cert_path = Path(tmp) / "cert.pem"
        subprocess.run(
            [
                "openssl", "req", "-x509", "-newkey", "rsa:2048", "-keyout", str(key_path),
                "-out", str(cert_path), "-days", "1", "-nodes",
                "-subj", "/CN=sim2real.example.com",
            ],
            check=True,
            capture_output=True,
        )
        cert_pem = cert_path.read_bytes()
        key_pem = key_path.read_bytes()
    resp = acm.import_certificate(Certificate=cert_pem, PrivateKey=key_pem)
    cert_arn = resp["CertificateArn"]
    ctx.on_cleanup(lambda: acm.delete_certificate(CertificateArn=cert_arn))
    return cert_arn


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
