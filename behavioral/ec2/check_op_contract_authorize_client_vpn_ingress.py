"""op-contract-authorizeClientVpnIngress."""
from __future__ import annotations

import datetime
import time
from typing import Any, Callable

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-authorizeClientVpnIngress"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """AuthorizeClientVpnIngress with DryRun fails DryRunOperation with its exact message and adds
    no rule, and the real call adds an AccessAll rule that reaches active in
    DescribeClientVpnAuthorizationRules.
    """
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
    # Registered before the endpoint, so it runs after the endpoint teardown (LIFO).
    ctx.on_cleanup(lambda: _delete_certificate(acm, cert_arn))

    endpoint = ec2.create_client_vpn_endpoint(
        ClientCidrBlock="10.222.0.0/22",
        ServerCertificateArn=cert_arn,
        AuthenticationOptions=[
            {"Type": "certificate-authentication", "MutualAuthentication": {"ClientRootCertificateChainArn": cert_arn}}
        ],
        ConnectionLogOptions={"Enabled": False},
        TagSpecifications=[
            {"ResourceType": "client-vpn-endpoint", "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-cvpn-")}]}
        ],
    )["ClientVpnEndpointId"]

    def cleanup_endpoint():
        _best_effort(lambda: ec2.delete_client_vpn_endpoint(ClientVpnEndpointId=endpoint))
        _best_effort(
            lambda: _poll_until(
                lambda: _endpoint_exists(ec2, endpoint),
                lambda exists: not exists,
                timeout_s=120,
                interval_s=5,
            )
        )

    ctx.on_cleanup(cleanup_endpoint)

    _poll_until(
        lambda: ec2.describe_client_vpn_endpoints(ClientVpnEndpointIds=[endpoint])["ClientVpnEndpoints"][0][
            "Status"
        ]["Code"],
        lambda code: code in ("pending-associate", "available"),
        timeout_s=60,
        interval_s=3,
    )

    # error boundary: DryRun must short-circuit with DryRunOperation before any mutation
    code, code_message = _error_code(
        lambda: ec2.authorize_client_vpn_ingress(
            ClientVpnEndpointId=endpoint, TargetNetworkCidr="203.0.113.0/24", AuthorizeAllGroups=True, DryRun=True
        )
    )
    assert code == "DryRunOperation", f"expected DryRunOperation, got {code}"
    expected_code_message = "Request would have succeeded, but DryRun flag is set."
    assert code_message == expected_code_message, f"expected message {expected_code_message!r}, got {code_message!r}"

    # independent read: DryRun must not have created the rule it declined to execute
    predryrun_rows = [
        r
        for r in ec2.describe_client_vpn_authorization_rules(ClientVpnEndpointId=endpoint)["AuthorizationRules"]
        if r["DestinationCidr"] == "203.0.113.0/24"
    ]
    assert predryrun_rows == [], f"DryRun mutated state: found rule(s) {predryrun_rows}"

    # success path
    ec2.authorize_client_vpn_ingress(
        ClientVpnEndpointId=endpoint, TargetNetworkCidr="203.0.113.0/24", AuthorizeAllGroups=True, Description="allow-all"
    )

    final = _poll_until(
        lambda: [
            r
            for r in ec2.describe_client_vpn_authorization_rules(ClientVpnEndpointId=endpoint)["AuthorizationRules"]
            if r["DestinationCidr"] == "203.0.113.0/24"
        ],
        lambda rows: bool(rows) and rows[0]["Status"]["Code"] == "active",
        timeout_s=60,
        interval_s=3,
    )
    assert final[0]["AccessAll"] is True
    assert final[0]["Status"]["Code"] == "active"


def _endpoint_exists(ec2, endpoint_id: str) -> bool:
    try:
        rows = ec2.describe_client_vpn_endpoints(ClientVpnEndpointIds=[endpoint_id])["ClientVpnEndpoints"]
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "InvalidClientVpnEndpointId.NotFound":
            raise
        return False
    if not rows:
        return False
    return rows[0]["Status"]["Code"] != "deleted"


_CERT_TEARDOWN_S = 300.0


def _delete_certificate(acm, cert_arn: str) -> None:
    """Delete the certificate. ACM answers ResourceInUseException while the deleted endpoint still
    holds it, so that answer is retried every 2 s within one deadline; already gone is fine."""
    deadline = time.monotonic() + _CERT_TEARDOWN_S
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


def _poll_until(probe: Callable[[], Any], predicate: Callable[[Any], bool], *, timeout_s: float, interval_s: float) -> Any:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _error_code(fn: Callable[[], Any]) -> tuple[str, str | None]:
    """Call fn() and return its (code, message); a call that succeeds raises."""
    try:
        result = fn()
    except Exception as exc:
        err = getattr(exc, "response", {}).get("Error")
        if not err:
            raise
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
