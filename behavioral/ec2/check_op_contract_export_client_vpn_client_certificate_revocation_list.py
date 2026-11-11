"""op-contract-export-client-vpn-client-certificate-revocation-list."""
from __future__ import annotations

import datetime
import time
from typing import Any, Callable

from behavioral_harness import tags

CHECK = "op-contract-export-client-vpn-client-certificate-revocation-list"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ExportClientVpnClientCertificateRevocationList returns a real PEM-encoded X509
    CRL for a certificate-authenticated Client VPN endpoint, and rejects a nonexistent
    endpoint id with the documented NotFound code."""
    import cryptography  # noqa: F401

    ec2 = ctx.client("ec2")
    acm = ctx.client("acm")

    server_arn, _, _ = _import_self_signed_cert(ctx, acm, "server.sim2real.example.com")
    ca_arn, ca_cert, ca_key = _import_self_signed_cert(ctx, acm, "ca.sim2real.example.com", is_ca=True)
    # Teardown runs LIFO: these certificate deletions run after the endpoint's teardown,
    # which waits until the endpoint is gone and has released both certificates.
    ctx.on_cleanup(lambda: _delete_certificate_when_released(acm, server_arn))
    ctx.on_cleanup(lambda: _delete_certificate_when_released(acm, ca_arn))

    endpoint_id = _retry_on_concurrent_creation(lambda: ec2.create_client_vpn_endpoint(
        ClientCidrBlock="10.77.0.0/22",
        ServerCertificateArn=server_arn,
        AuthenticationOptions=[{
            "Type": "certificate-authentication",
            "MutualAuthentication": {"ClientRootCertificateChainArn": ca_arn},
        }],
        ConnectionLogOptions={"Enabled": False},
        TagSpecifications=[{
            "ResourceType": "client-vpn-endpoint",
            "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-cvpn-")}],
        }],
    ))["ClientVpnEndpointId"]
    ctx.on_cleanup(lambda: _delete_endpoint_and_wait(ec2, endpoint_id))

    _wait_for(lambda: _endpoint_not_creating(ec2, endpoint_id), timeout_s=180)

    # Real AWS does not synthesize a CRL out of thin air: ExportClientVpnClientCertificateRevocationList
    # only returns a CertificateRevocationList once one has actually been uploaded via
    # ImportClientVpnClientCertificateRevocationList, so mint a real (empty-revocation)
    # CRL signed by the client root CA and import it first.
    _import_crl(ec2, endpoint_id, ca_cert, ca_key)

    # --- success path: a real certificate revocation list is exported ---
    resp = _wait_for_crl(ec2, endpoint_id)
    crl = resp["CertificateRevocationList"]
    assert "-----BEGIN X509 CRL-----" in crl, crl[:80]
    assert resp["Status"]["Code"] == "active", resp["Status"]

    # --- error boundary: nonexistent Client VPN endpoint id ---
    code, message = _error(lambda: ec2.export_client_vpn_client_certificate_revocation_list(
        ClientVpnEndpointId="cvpn-endpoint-00000000000000000"
    ))
    assert code == "InvalidClientVpnEndpointId.NotFound", code
    assert message == "Endpoint cvpn-endpoint-00000000000000000 does not exist", message


def _import_self_signed_cert(ctx, acm: Any, common_name: str, is_ca: bool = False):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    now = datetime.datetime.utcnow()
    builder = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=3))
        .add_extension(x509.BasicConstraints(ca=is_ca, path_length=None), critical=True)
    )
    cert = builder.sign(key, hashes.SHA256())
    key_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    arn = acm.import_certificate(Certificate=cert_pem, PrivateKey=key_pem)["CertificateArn"]
    return arn, cert, key


def _import_crl(ec2: Any, endpoint_id: str, ca_cert: Any, ca_key: Any) -> None:
    """Mint a real (initially empty-revocation) X509 CRL signed by the client root
    CA and upload it, since ExportClientVpnClientCertificateRevocationList only
    returns a CertificateRevocationList once one has been imported."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization

    now = datetime.datetime.utcnow()
    crl = (
        x509.CertificateRevocationListBuilder()
        .issuer_name(ca_cert.subject)
        .last_update(now)
        .next_update(now + datetime.timedelta(days=7))
        .sign(private_key=ca_key, algorithm=hashes.SHA256())
    )
    crl_pem = crl.public_bytes(serialization.Encoding.PEM).decode()
    ec2.import_client_vpn_client_certificate_revocation_list(
        ClientVpnEndpointId=endpoint_id, CertificateRevocationList=crl_pem
    )


def _wait_for_crl(ec2: Any, endpoint_id: str, timeout_s: float = 90.0, interval_s: float = 5.0) -> dict:
    """Right after the Client VPN endpoint transitions out of "creating", CRL
    generation is still in progress server-side: ExportClientVpnClientCertificateRevocationList
    can return a response that only carries the Status field and omits
    CertificateRevocationList entirely, and the CRL status starts pending. Poll until the CRL
    content shows up with status active."""
    deadline = time.monotonic() + timeout_s
    last_resp: Any = None
    while time.monotonic() < deadline:
        resp = ec2.export_client_vpn_client_certificate_revocation_list(ClientVpnEndpointId=endpoint_id)
        last_resp = resp
        if resp.get("CertificateRevocationList") and resp.get("Status", {}).get("Code") == "active":
            return resp
        time.sleep(interval_s)
    raise AssertionError(f"an active CertificateRevocationList never appeared in export response: {last_resp}")


def _endpoint_not_creating(ec2: Any, endpoint_id: str) -> bool:
    eps = ec2.describe_client_vpn_endpoints(ClientVpnEndpointIds=[endpoint_id])["ClientVpnEndpoints"]
    return eps[0]["Status"]["Code"] != "creating"


def _retry_on_concurrent_creation(fn: Callable[[], Any], timeout_s: float = 180.0, interval_s: float = 5.0) -> Any:
    """The account/region only allows one Client VPN endpoint to be in the
    "creating" state at a time; CreateClientVpnEndpoint rejects a concurrent
    attempt with OperationNotPermitted rather than queuing it, so retry until the
    other endpoint finishes creating."""
    from botocore.exceptions import ClientError
    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            return fn()
        except ClientError as exc:
            last_exc = exc
            msg = exc.response["Error"].get("Message", "")
            if exc.response["Error"]["Code"] != "OperationNotPermitted" or "being created" not in msg:
                raise
            time.sleep(interval_s)
    raise last_exc  # type: ignore[misc]


def _delete_endpoint_and_wait(ec2: Any, endpoint_id: str, timeout_s: float = 600.0) -> None:
    """Delete the Client VPN endpoint and wait until it is gone, so the ACM certificates it
    references are released before their own teardown runs."""
    from botocore.exceptions import ClientError
    try:
        ec2.delete_client_vpn_endpoint(ClientVpnEndpointId=endpoint_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "InvalidClientVpnEndpointId.NotFound":
            raise
        return
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            eps = ec2.describe_client_vpn_endpoints(ClientVpnEndpointIds=[endpoint_id])["ClientVpnEndpoints"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "InvalidClientVpnEndpointId.NotFound":
                return
            raise
        if not eps or eps[0]["Status"]["Code"] == "deleted":
            return
        time.sleep(5)
    raise AssertionError(f"Client VPN endpoint {endpoint_id} was not deleted within {timeout_s}s")


def _delete_certificate_when_released(acm: Any, arn: str, timeout_s: float = 300.0) -> None:
    """Delete an ACM certificate, retrying while a just-deleted Client VPN endpoint still holds it."""
    from botocore.exceptions import ClientError
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            acm.delete_certificate(CertificateArn=arn)
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "ResourceNotFoundException":
                return
            if code != "ResourceInUseException" or time.monotonic() >= deadline:
                raise
        time.sleep(10)


def _wait_for(predicate: Callable[[], bool], timeout_s: float = 60.0, interval_s: float = 3.0) -> None:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(interval_s)
    raise AssertionError("condition not met within timeout")


def _error(fn: Callable[[], Any]) -> tuple[str, str]:
    """Call fn() and return the (code, message) of the ClientError it raises. A call
    that succeeds raises AssertionError, because an emulator accepting what real AWS
    refuses must not read as a mere code mismatch."""
    from botocore.exceptions import ClientError
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
