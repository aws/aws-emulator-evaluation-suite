"""client-vpn-endpoint-authorization-policy-lifecycle."""
from __future__ import annotations

import datetime
import time
from typing import Any, Callable

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "client-vpn-endpoint-authorization-policy-lifecycle"
GROUP = "client-vpn"
SERVICES = ["ec2", "acm"]

_POLICY_V1 = 'permit(principal, action, resource);'
_POLICY_V1_DESCRIPTION = "sim2real allow-all authorization policy"
_POLICY_V2 = 'forbid(principal, action, resource);'
_POLICY_V2_DESCRIPTION = "sim2real deny-all authorization policy"


def _poll_until(probe: Callable[[], Any], predicate: Callable[[Any], bool], *, timeout_s: float = 120.0,
                interval_s: float = 3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s, last observed value: {last!r}")


def _delete_certificate(acm, cert_arn: str, *, timeout_s: float = 300.0) -> None:
    """Delete the certificate; ACM answers ResourceInUseException while the deleted endpoint
    still references it, so that answer is retried until a deadline, and already-gone is fine."""
    deadline = time.monotonic() + timeout_s
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


def _unless_gone(fn: Callable[[], Any]) -> None:
    """Run a teardown step; only the endpoint's own not-found means it is already gone."""
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "InvalidClientVpnEndpointId.NotFound":
            raise


def _create_self_signed_certificate(acm):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

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
    return acm.import_certificate(Certificate=cert_pem, PrivateKey=key_pem)["CertificateArn"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A Cedar authorization policy set by Modify reads back once active; a further Modify
    omitting PolicyDocument changes only the other fields, leaving it unchanged; and after
    Delete, a Modify applies its own new document rather than reapplying the deleted one.
    """
    ec2 = ctx.client("ec2")
    acm = ctx.client("acm")

    cert_arn = _create_self_signed_certificate(acm)
    # Registered before the endpoint, so it runs after the endpoint teardown (LIFO).
    ctx.on_cleanup(lambda: _delete_certificate(acm, cert_arn))

    endpoint = ec2.create_client_vpn_endpoint(
        ClientCidrBlock="10.223.0.0/22",
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

    def _cleanup_endpoint():
        _unless_gone(lambda: ec2.delete_client_vpn_endpoint(ClientVpnEndpointId=endpoint))
        _unless_gone(
            lambda: _poll_until(
                lambda: _endpoint_exists(ec2, endpoint),
                lambda exists: not exists,
                timeout_s=120,
                interval_s=5,
            )
        )

    ctx.on_cleanup(_cleanup_endpoint)

    _poll_until(
        lambda: ec2.describe_client_vpn_endpoints(ClientVpnEndpointIds=[endpoint])["ClientVpnEndpoints"][
            0
        ]["Status"]["Code"],
        lambda code: code in ("pending-associate", "available"),
        timeout_s=60,
    )

    created = ec2.modify_client_vpn_endpoint_authorization_policy(
        ClientVpnEndpointId=endpoint,
        PolicyDocument=_POLICY_V1,
        Description=_POLICY_V1_DESCRIPTION,
        ShadowMode="enabled",
    )
    assert created["Status"] in ("creating", "updating"), (
        f"expected Status creating/updating right after the first Modify, got {created['Status']!r}"
    )

    active = _poll_until(
        lambda: ec2.get_client_vpn_endpoint_authorization_policy(ClientVpnEndpointId=endpoint),
        lambda p: p["Status"] == "active",
    )
    assert active["PolicyDocument"] == _POLICY_V1, (
        f"expected PolicyDocument {_POLICY_V1!r} once active, got {active['PolicyDocument']!r}"
    )
    assert active["Description"] == _POLICY_V1_DESCRIPTION, (
        f"expected Description {_POLICY_V1_DESCRIPTION!r}, got {active['Description']!r}"
    )
    assert active["ShadowMode"] == "enabled", (
        f"expected ShadowMode 'enabled', got {active['ShadowMode']!r}"
    )

    # A Modify that omits PolicyDocument must leave it unchanged while applying only the
    # fields given -- here, flipping ShadowMode to 'disabled'.
    toggled = ec2.modify_client_vpn_endpoint_authorization_policy(
        ClientVpnEndpointId=endpoint, ShadowMode="disabled"
    )
    assert toggled["Status"] in ("creating", "updating"), (
        f"expected Status creating/updating right after the second Modify, got {toggled['Status']!r}"
    )
    active_again = _poll_until(
        lambda: ec2.get_client_vpn_endpoint_authorization_policy(ClientVpnEndpointId=endpoint),
        lambda p: p["Status"] == "active" and p["ShadowMode"] == "disabled",
    )
    assert active_again["PolicyDocument"] == _POLICY_V1, (
        f"omitting PolicyDocument on the second Modify must leave it unchanged, "
        f"expected {_POLICY_V1!r}, got {active_again['PolicyDocument']!r}"
    )
    assert active_again["Description"] == _POLICY_V1_DESCRIPTION, (
        f"omitting Description on the second Modify must leave it unchanged, "
        f"expected {_POLICY_V1_DESCRIPTION!r}, got {active_again['Description']!r}"
    )

    deleted = ec2.delete_client_vpn_endpoint_authorization_policy(ClientVpnEndpointId=endpoint)
    assert deleted["Status"] == "deleting", (
        f"expected Status 'deleting' right after Delete, got {deleted['Status']!r}"
    )

    # While the deletion is still in flight, a Modify can be refused with IncorrectState;
    # that is retried on a bounded deadline, never treated as the terminal outcome.
    _retry_until_accepted(
        lambda: ec2.modify_client_vpn_endpoint_authorization_policy(
            ClientVpnEndpointId=endpoint,
            PolicyDocument=_POLICY_V2,
            Description=_POLICY_V2_DESCRIPTION,
            ShadowMode="disabled",
        ),
        retry_on=("IncorrectState",),
        timeout_s=300,
    )
    recreated = _poll_until(
        lambda: ec2.get_client_vpn_endpoint_authorization_policy(ClientVpnEndpointId=endpoint),
        lambda p: p["Status"] == "active",
        timeout_s=300,
    )
    assert recreated["PolicyDocument"] == _POLICY_V2, (
        f"a Modify issued after Delete must apply its own document {_POLICY_V2!r}, "
        f"not the deleted v1 document; got {recreated['PolicyDocument']!r}"
    )
    assert recreated["Description"] == _POLICY_V2_DESCRIPTION, (
        f"expected Description {_POLICY_V2_DESCRIPTION!r} on the recreated policy, "
        f"got {recreated['Description']!r}"
    )


def _retry_until_accepted(fn, *, retry_on: tuple[str, ...], timeout_s: float, interval_s: float = 5.0):
    """Call fn(); retry only the exact transient codes in retry_on until it is accepted."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return fn()
        except ClientError as exc:
            if exc.response["Error"]["Code"] not in retry_on or time.monotonic() >= deadline:
                raise
        time.sleep(interval_s)


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


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
