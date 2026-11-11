"""op-contract-describe-client-vpn-authorization-rules."""
from __future__ import annotations

import datetime
import time
from typing import Any, Callable

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-describe-client-vpn-authorization-rules"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DescribeClientVpnAuthorizationRules on a new Client VPN endpoint returns no rules; on a
    nonexistent endpoint DryRun answers DryRunOperation and the real call fails with
    InvalidClientVpnEndpointId.NotFound (exact messages)."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    ec2 = ctx.client("ec2")
    acm = ctx.client("acm")

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "sim2real.example.com")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    key_pem = key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    )
    cert_arn = acm.import_certificate(Certificate=cert_pem, PrivateKey=key_pem)["CertificateArn"]
    # Both teardowns share one deadline, set when the first of them starts.
    teardown_deadline: list = []

    def _deadline() -> float:
        if not teardown_deadline:
            teardown_deadline.append(time.monotonic() + _CLEANUP_S)
        return teardown_deadline[0]

    ctx.on_cleanup(lambda: _delete_certificate(acm, cert_arn, _deadline()))

    endpoint = ec2.create_client_vpn_endpoint(
        ClientCidrBlock="10.234.0.0/22",
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
                "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-cvpn-")}],
            }
        ],
    )["ClientVpnEndpointId"]

    def cleanup_endpoint():
        _best_effort(lambda: ec2.delete_client_vpn_endpoint(ClientVpnEndpointId=endpoint))
        deadline = _deadline()
        while _endpoint_exists(ec2, endpoint):
            if time.monotonic() >= deadline:
                raise RuntimeError(f"client vpn endpoint {endpoint} still present at the cleanup deadline")
            time.sleep(2)

    ctx.on_cleanup(cleanup_endpoint)

    _poll_until(
        lambda: ec2.describe_client_vpn_endpoints(ClientVpnEndpointIds=[endpoint])[
            "ClientVpnEndpoints"
        ][0]["Status"]["Code"],
        lambda code: code in ("pending-associate", "available"),
        timeout_s=60,
        interval_s=3,
    )

    # positive control: a real, freshly created endpoint has no rules yet, but the call
    # itself must succeed cleanly against it.
    positive = ec2.describe_client_vpn_authorization_rules(ClientVpnEndpointId=endpoint)
    assert positive["AuthorizationRules"] == [], (
        f"expected no authorization rules on a freshly created endpoint, "
        f"got {positive['AuthorizationRules']!r}"
    )

    fake_endpoint_id = "cvpn-endpoint-0000000000000000"

    dry_code, dry_code_msg = _error(
        lambda: ec2.describe_client_vpn_authorization_rules(
            ClientVpnEndpointId=fake_endpoint_id, DryRun=True
        )
    )
    assert dry_code == "DryRunOperation", f"expected DryRunOperation, got {dry_code}"
    assert dry_code_msg == "Request would have succeeded, but DryRun flag is set.", (
        f"expected the exact DryRunOperation message, got {dry_code_msg!r}"
    )

    not_found_code, not_found_code_msg = _error(
        lambda: ec2.describe_client_vpn_authorization_rules(
            ClientVpnEndpointId=fake_endpoint_id
        )
    )
    assert not_found_code == "InvalidClientVpnEndpointId.NotFound", (
        f"expected InvalidClientVpnEndpointId.NotFound, got {not_found_code}"
    )
    assert not_found_code_msg == f"Endpoint {fake_endpoint_id} does not exist", (
        f"expected the exact InvalidClientVpnEndpointId.NotFound message, got {not_found_code_msg!r}"
    )


def _endpoint_exists(ec2, endpoint_id: str) -> bool:
    try:
        rows = ec2.describe_client_vpn_endpoints(ClientVpnEndpointIds=[endpoint_id])[
            "ClientVpnEndpoints"
        ]
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "InvalidClientVpnEndpointId.NotFound":
            raise
        return False
    if not rows:
        return False
    return rows[0]["Status"]["Code"] != "deleted"


# The suite's cleanup budget, shared by the endpoint and certificate teardowns.
_CLEANUP_S = 900.0


def _delete_certificate(acm, cert_arn: str, deadline: float) -> None:
    """Delete the certificate, retrying ResourceInUseException every 2 s while the endpoint that uses
    it is still deleting; not-found means gone, anything else raises."""
    while True:
        try:
            acm.delete_certificate(CertificateArn=cert_arn)
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "ResourceNotFoundException":
                return
            if code != "ResourceInUseException" or time.monotonic() >= deadline:
                raise
        time.sleep(2)


def _best_effort(fn: Callable[[], Any]) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "InvalidClientVpnEndpointId.NotFound",
            "ResourceNotFoundException",
        ):
            raise


def _poll_until(
    probe: Callable[[], Any], predicate: Callable[[Any], bool], *, timeout_s: float, interval_s: float
) -> Any:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _error(fn):
    """Call fn(); return its botocore error (Code, Message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
