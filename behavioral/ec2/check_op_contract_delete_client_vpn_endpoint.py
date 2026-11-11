"""op-contract-deleteClientVpnEndpoint."""
from __future__ import annotations

import os
import subprocess
import tempfile
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-deleteClientVpnEndpoint"
GROUP = "error-semantics"
SERVICES = ["ec2"]

_DRY_RUN_MESSAGE = "Request would have succeeded, but DryRun flag is set."


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeleteClientVpnEndpoint: success tears down a certificate-authenticated endpoint and
    the endpoint is then gone; a nonexistent ClientVpnEndpointId is rejected."""
    ec2 = ctx.client("ec2")
    acm = ctx.client("acm")

    cert_pem, key_pem = _self_signed_cert_pem()
    cert_arn = acm.import_certificate(
        Certificate=cert_pem, PrivateKey=key_pem, Tags=[{"Key": "sim2real", "Value": CHECK}]
    )["CertificateArn"]
    ctx.on_cleanup(lambda: acm.delete_certificate(CertificateArn=cert_arn))

    resp = ec2.create_client_vpn_endpoint(
        ClientCidrBlock="10.99.0.0/22",
        ServerCertificateArn=cert_arn,
        AuthenticationOptions=[
            {
                "Type": "certificate-authentication",
                "MutualAuthentication": {"ClientRootCertificateChainArn": cert_arn},
            }
        ],
        ConnectionLogOptions={"Enabled": False},
        Description=ctx.unique_name("sim2real-cvpn-"),
        TagSpecifications=[
            {"ResourceType": "client-vpn-endpoint", "Tags": [{"Key": "sim2real", "Value": CHECK}]}
        ],
    )
    endpoint_id = resp["ClientVpnEndpointId"]

    def _cleanup() -> None:
        try:
            ec2.delete_client_vpn_endpoint(ClientVpnEndpointId=endpoint_id)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "InvalidClientVpnEndpointId.NotFound":
                raise

    ctx.on_cleanup(_cleanup)

    # With no target network, the endpoint settles in pending-associate.
    described = _poll_until(
        lambda: ec2.describe_client_vpn_endpoints(ClientVpnEndpointIds=[endpoint_id])["ClientVpnEndpoints"][0],
        lambda e: e["Status"]["Code"] == "pending-associate",
        timeout_s=40,
    )
    assert described["ClientVpnEndpointId"] == endpoint_id, described

    # Error boundary: DryRun must short-circuit before the delete is applied.
    err = _client_error(
        lambda: ec2.delete_client_vpn_endpoint(ClientVpnEndpointId=endpoint_id, DryRun=True)
    )
    assert err.get("Code") == "DryRunOperation", f"expected DryRunOperation, got {err!r}"
    assert err.get("Message") == _DRY_RUN_MESSAGE, f"unexpected DryRun message: {err!r}"

    ec2.delete_client_vpn_endpoint(ClientVpnEndpointId=endpoint_id)

    # Independent read: the endpoint itself, not the delete call's own response, must show
    # the deletion took effect.
    final_status = _wait_for_terminal_status(ec2, endpoint_id)
    assert final_status in ("deleted", "gone"), f"expected deleted/gone, got {final_status!r}"

    # Error boundary: the now-deleted endpoint is rejected as not-found, and is unusable.
    err2 = _client_error(lambda: ec2.delete_client_vpn_endpoint(ClientVpnEndpointId=endpoint_id))
    assert err2.get("Code") == "InvalidClientVpnEndpointId.NotFound", f"expected InvalidClientVpnEndpointId.NotFound, got {err2!r}"
    assert err2.get("Message") == _not_found_message(endpoint_id), f"unexpected not-found message: {err2!r}"

    # Error boundary: a fabricated, never-existing ClientVpnEndpointId is rejected identically.
    err3 = _client_error(
        lambda: ec2.delete_client_vpn_endpoint(ClientVpnEndpointId="cvpn-endpoint-00000000000000000")
    )
    assert err3.get("Code") == "InvalidClientVpnEndpointId.NotFound", f"expected InvalidClientVpnEndpointId.NotFound, got {err3!r}"
    assert err3.get("Message") == _not_found_message("cvpn-endpoint-00000000000000000"), (
        f"unexpected not-found message: {err3!r}"
    )


def _poll_until(probe, predicate, timeout_s, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


def _client_error(fn):
    """Call fn(); return its botocore Error dict. An unexpected success raises AssertionError."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")


def _not_found_message(endpoint_id):
    return f"Endpoint {endpoint_id} does not exist"


def _wait_for_terminal_status(ec2, endpoint_id, timeout_s=150, interval_s=5):
    """Poll the endpoint by an independent describe call until it reaches a deleted/gone
    terminal state, bounded by a deadline. Raises on timeout rather than returning a
    non-terminal value."""
    import time

    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    last_status = None
    while time.monotonic() < deadline:
        try:
            resp = ec2.describe_client_vpn_endpoints(ClientVpnEndpointIds=[endpoint_id])
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "InvalidClientVpnEndpointId.NotFound":
                return "gone"
            raise
        endpoints = resp.get("ClientVpnEndpoints", [])
        if not endpoints:
            return "gone"
        last_status = endpoints[0]["Status"]["Code"]
        if last_status == "deleted":
            return "deleted"
        time.sleep(interval_s)
    raise AssertionError(
        f"client VPN endpoint {endpoint_id} did not reach a terminal deleted state within "
        f"{timeout_s}s (last observed status={last_status!r})"
    )


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
                    "-subj", "/CN=sim2real-cvpn.example.com",
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


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
