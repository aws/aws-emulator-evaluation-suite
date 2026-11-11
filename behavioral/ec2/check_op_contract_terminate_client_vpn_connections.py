"""op-contract-terminate-client-vpn-connections."""
from __future__ import annotations

import subprocess
import tempfile
from pathlib import Path

from behavioral_harness import tags

CHECK = "op-contract-terminate-client-vpn-connections"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """TerminateClientVpnConnections rejects a username with no active connections on a real
    endpoint (nothing to terminate); bogus ClientVpnEndpointId is rejected."""
    from fidelity_tests_runner import require_tools

    require_tools("openssl")

    cert_pem, key_pem = _generate_self_signed_pem()

    acm = ctx.client("acm")
    cert_arn = acm.import_certificate(Certificate=cert_pem, PrivateKey=key_pem)["CertificateArn"]
    ctx.on_cleanup(lambda: acm.delete_certificate(CertificateArn=cert_arn))

    ec2 = ctx.client("ec2")
    endpoint_id = ec2.create_client_vpn_endpoint(
        ClientCidrBlock="10.220.0.0/22",
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
    ctx.on_cleanup(lambda: ec2.delete_client_vpn_endpoint(ClientVpnEndpointId=endpoint_id))

    # rejection boundary: real EC2 rejects TerminateClientVpnConnections for a username
    # that has never had an active connection on this endpoint -- there is nothing to
    # terminate, so it is an error rather than a no-op success.
    code, message = _error(
        lambda: ec2.terminate_client_vpn_connections(
            ClientVpnEndpointId=endpoint_id, Username="sim2real-behavioral-probe"
        )
    )
    assert code == "InvalidClientVpnConnection.UserNotFound", (
        f"expected InvalidClientVpnConnection.UserNotFound, got {code!r}"
    )
    assert message == "No connections exists for the given username sim2real-behavioral-probe", (
        f"unexpected InvalidClientVpnConnection.UserNotFound message {message!r}")

    # error boundary: nonexistent client vpn endpoint id. A hand-picked id string can
    # have the wrong hex length for the current id format; real EC2 then fails request
    # validation in a way that surfaces as an opaque InternalError instead of the
    # intended NotFound. Derive a same-length/charset id from the real endpoint we just
    # created (by rotating its last hex digit) so the shape is guaranteed valid while
    # the id itself doesn't correspond to any endpoint. TerminateClientVpnConnections
    # requires either Username or ConnectionId regardless of endpoint validity, so a
    # Username must still be supplied here or real EC2 rejects the request with
    # MissingParameter before it ever gets to validate the (bogus) endpoint id.
    bogus_id = _mutate_last_hex_char(endpoint_id)
    code, message = _error(
        lambda: ec2.terminate_client_vpn_connections(
            ClientVpnEndpointId=bogus_id,
            Username="sim2real-behavioral-probe",
        )
    )
    assert code == "InvalidClientVpnEndpointId.NotFound", (
        f"expected InvalidClientVpnEndpointId.NotFound, got {code!r}"
    )
    assert message == f"Endpoint {bogus_id} does not exist", (
        f"unexpected InvalidClientVpnEndpointId.NotFound message {message!r}")


def _mutate_last_hex_char(resource_id: str) -> str:
    prefix, last = resource_id[:-1], resource_id[-1]
    rotated = format((int(last, 16) + 1) % 16, "x")
    return prefix + rotated


def _error(fn):
    """Call fn() and return the (code, message) of the ClientError it raises; a call that
    succeeds raises AssertionError."""
    from botocore.exceptions import ClientError
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded with {result!r}")


def _generate_self_signed_pem():
    with tempfile.TemporaryDirectory() as tmp:
        key_path = Path(tmp) / "key.pem"
        cert_path = Path(tmp) / "cert.pem"
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
                "-subj",
                "/CN=sim2real.behavioral.test",
                "-keyout",
                str(key_path),
                "-out",
                str(cert_path),
            ],
            check=True,
            capture_output=True,
        )
        return cert_path.read_bytes(), key_path.read_bytes()


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
