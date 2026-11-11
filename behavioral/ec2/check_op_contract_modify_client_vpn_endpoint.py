"""op-contract-modify-client-vpn-endpoint."""
from __future__ import annotations

import subprocess
import tempfile
import time
from pathlib import Path

from behavioral_harness import tags
from botocore.exceptions import ClientError
from fidelity_tests_runner import require_tools

CHECK = "op-contract-modify-client-vpn-endpoint"
GROUP = "error-semantics"
SERVICES = ["ec2"]
DRY_RUN_MESSAGE = "Request would have succeeded, but DryRun flag is set."
_CREATE_BUSY_DEADLINE_S = 300.0


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ModifyClientVpnEndpoint updates endpoint config; DryRun and unknown endpoint id are rejected."""
    from botocore.exceptions import ClientError

    cert_pem, key_pem = _generate_self_signed_cert()

    acm = ctx.client("acm")
    cert_arn = acm.import_certificate(Certificate=cert_pem, PrivateKey=key_pem)["CertificateArn"]
    ctx.on_cleanup(lambda: _delete_cert(acm, cert_arn))

    ec2 = ctx.client("ec2")
    description = ctx.unique_name("sim2real-cvpn-")
    name_tag = ctx.unique_name("sim2real-cvpn-")
    # AWS refuses a create while another endpoint in the account is being created; retry that refusal.
    left = ctx.time_left()
    deadline = time.monotonic() + (_CREATE_BUSY_DEADLINE_S if left is None else min(_CREATE_BUSY_DEADLINE_S, left))
    while True:
        try:
            created = ec2.create_client_vpn_endpoint(
                ClientCidrBlock="10.213.0.0/22",
                ServerCertificateArn=cert_arn,
                AuthenticationOptions=[
                    {
                        "Type": "certificate-authentication",
                        "MutualAuthentication": {"ClientRootCertificateChainArn": cert_arn},
                    }
                ],
                ConnectionLogOptions={"Enabled": False},
                Description=description,
                TagSpecifications=[
                    {
                        "ResourceType": "client-vpn-endpoint",
                        "Tags": [{"Key": "Name", "Value": name_tag}],
                    }
                ],
            )
            break
        except ClientError as e:
            err = e.response["Error"]
            busy = (err["Code"] == "OperationNotPermitted"
                    and "while another endpoint is being created" in err.get("Message", ""))
            if busy and time.monotonic() < deadline:
                time.sleep(2)
                continue
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

    # --- error boundary #1: DryRun must reject before applying the update ---
    dry_code, dry_msg = _error(
        lambda: ec2.modify_client_vpn_endpoint(
            ClientVpnEndpointId=endpoint_id, Description="dry-run-probe", DryRun=True
        )
    )
    assert dry_code == "DryRunOperation", f"expected DryRunOperation, got {dry_code!r}"
    assert dry_msg == DRY_RUN_MESSAGE, f"expected message {DRY_RUN_MESSAGE!r}, got {dry_msg!r}"

    # --- error boundary #2: an unknown endpoint id must be rejected distinctly ---
    notfound_code, notfound_msg = _error(
        lambda: ec2.modify_client_vpn_endpoint(
            ClientVpnEndpointId="cvpn-endpoint-000000000000000", SelfServicePortal="enabled"
        )
    )
    assert notfound_code == "InvalidClientVpnEndpointId.NotFound", (
        f"unexpected error code: {notfound_code!r}"
    )
    expected_notfound = "Endpoint cvpn-endpoint-000000000000000 does not exist"
    assert notfound_msg == expected_notfound, f"expected message {expected_notfound!r}, got {notfound_msg!r}"

    # --- success path: modify description and self-service portal, observe both take effect ---
    # DescribeClientVpnEndpoints does not echo the request-side "SelfServicePortal" enum back
    # under that same key; when enabled it instead exposes a "SelfServicePortalUrl" (populated
    # only once the portal is actually enabled), so poll on that instead.
    new_description = ctx.unique_name("sim2real-cvpn-updated-")
    resp = ec2.modify_client_vpn_endpoint(
        ClientVpnEndpointId=endpoint_id,
        Description=new_description,
        SelfServicePortal="enabled",
    )
    assert resp["Return"] is True, f"expected Return=True, got {resp.get('Return')!r}"

    described = _poll_until(
        lambda: ec2.describe_client_vpn_endpoints(ClientVpnEndpointIds=[endpoint_id])[
            "ClientVpnEndpoints"
        ][0],
        lambda e: bool(e.get("SelfServicePortalUrl")),
        timeout_s=600.0,
        interval_s=10.0,
    )
    assert described["Description"] == new_description, (
        f"expected Description {new_description!r}, got {described['Description']!r}"
    )
    assert described.get("SelfServicePortalUrl"), (
        f"expected a populated SelfServicePortalUrl once enabled, got {described!r}"
    )


def _error(fn):
    """Call fn(); return the (code, message) of its ClientError. An unexpected SUCCESS raises,
    so a target that accepts what AWS refuses fails loudly instead of as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        err = e.response["Error"]
        return err["Code"], err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


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
