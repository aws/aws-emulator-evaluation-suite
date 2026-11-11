"""op-contract-describe-client-vpn-connections."""
from __future__ import annotations

import subprocess
import tempfile
import time
from pathlib import Path

from botocore.exceptions import ClientError
from fidelity_tests_runner import require_tools

from behavioral_harness import tags

CHECK = "op-contract-describe-client-vpn-connections"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DescribeClientVpnConnections on a new Client VPN endpoint returns no connections; on a
    nonexistent endpoint DryRun answers DryRunOperation and the real call fails with
    InvalidClientVpnEndpointId.NotFound (exact messages)."""
    ec2 = ctx.client("ec2")
    acm = ctx.client("acm")

    cert_pem, key_pem = _generate_self_signed_cert()
    cert_arn = acm.import_certificate(Certificate=cert_pem, PrivateKey=key_pem)["CertificateArn"]
    ctx.on_cleanup(lambda: _delete_cert(acm, cert_arn))

    try:
        created = ec2.create_client_vpn_endpoint(
            ClientCidrBlock="10.221.0.0/22",
            ServerCertificateArn=cert_arn,
            AuthenticationOptions=[
                {
                    "Type": "certificate-authentication",
                    "MutualAuthentication": {"ClientRootCertificateChainArn": cert_arn},
                }
            ],
            ConnectionLogOptions={"Enabled": False},
            Description=ctx.unique_name("sim2real-cvpn-conn-"),
            TagSpecifications=[
                {
                    "ResourceType": "client-vpn-endpoint",
                    "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-cvpn-conn-")}],
                }
            ],
        )
    except ClientError as e:
        raise AssertionError(f"CreateClientVpnEndpoint unavailable: {e}")

    endpoint_id = created["ClientVpnEndpointId"]
    ctx.on_cleanup(lambda: _delete_endpoint(ec2, endpoint_id))

    _poll_until(
        lambda: ec2.describe_client_vpn_endpoints(ClientVpnEndpointIds=[endpoint_id])[
            "ClientVpnEndpoints"
        ][0]["Status"]["Code"],
        lambda code: code in {"available", "pending-associate"},
        timeout_s=120.0,
        interval_s=5.0,
    )

    # Positive control: a real, freshly created endpoint describes cleanly with no
    # connections, proving DescribeClientVpnConnections itself works.
    resp = ec2.describe_client_vpn_connections(ClientVpnEndpointId=endpoint_id)
    assert resp["Connections"] == [], (
        f"expected no connections on a freshly created endpoint, got {resp['Connections']!r}"
    )

    fake_endpoint_id = "cvpn-endpoint-" + "0" * 17

    dry_code, dry_code_msg = _error(
        lambda: ec2.describe_client_vpn_connections(
            ClientVpnEndpointId=fake_endpoint_id, DryRun=True
        )
    )
    assert dry_code == "DryRunOperation", f"expected DryRunOperation, got {dry_code}"
    assert dry_code_msg == "Request would have succeeded, but DryRun flag is set.", (
        f"expected the exact DryRunOperation message, got {dry_code_msg!r}"
    )

    not_found_code, not_found_code_msg = _error(
        lambda: ec2.describe_client_vpn_connections(ClientVpnEndpointId=fake_endpoint_id)
    )
    assert not_found_code == "InvalidClientVpnEndpointId.NotFound", (
        f"expected InvalidClientVpnEndpointId.NotFound, got {not_found_code}"
    )
    assert not_found_code_msg == f"Endpoint {fake_endpoint_id} does not exist", (
        f"expected the exact InvalidClientVpnEndpointId.NotFound message, got {not_found_code_msg!r}"
    )


def _error(fn):
    """Call fn(); return its botocore error (Code, Message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


def _generate_self_signed_cert() -> tuple[bytes, bytes]:
    with tempfile.TemporaryDirectory() as tmp:
        key_path = Path(tmp) / "key.pem"
        cert_path = Path(tmp) / "cert.pem"
        require_tools("openssl")
        try:
            subprocess.run(
                [
                    "openssl",
                    "req",
                    "-x509",
                    "-newkey",
                    "rsa:2048",
                    "-days",
                    "2",
                    "-nodes",
                    "-keyout",
                    str(key_path),
                    "-out",
                    str(cert_path),
                    "-subj",
                    "/CN=sim2real.behavioral.test",
                ],
                check=True,
                capture_output=True,
                timeout=30,
            )
        except subprocess.CalledProcessError as e:
            raise AssertionError(f"openssl failed to generate a test certificate: {e.stderr!r}")
        return cert_path.read_bytes(), key_path.read_bytes()


def _delete_cert(acm, cert_arn: str) -> None:
    try:
        acm.delete_certificate(CertificateArn=cert_arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _delete_endpoint(ec2, endpoint_id: str) -> None:
    try:
        ec2.delete_client_vpn_endpoint(ClientVpnEndpointId=endpoint_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "InvalidClientVpnEndpointId.NotFound":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
