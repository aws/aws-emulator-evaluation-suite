"""put-and-reset-notification-settings."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "put-and-reset-notification-settings"
GROUP = "data-plane"
SERVICES = ["rolesanywhere"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A fresh trust anchor exposes the documented IAM Roles Anywhere default
    notification setting (threshold=45, configuredBy=rolesanywhere.amazonaws.com);
    PutNotificationSettings overrides it and ResetNotificationSettings reverts it."""
    ca_pem = _generate_ca_pem(ctx.unique_name("sim2real-ra-ca-"))

    ra = ctx.client("rolesanywhere")
    account_id = ctx.client("sts").get_caller_identity()["Account"]

    created = ra.create_trust_anchor(
        name=ctx.unique_name("sim2real-ra-ta-"),
        source={"sourceType": "CERTIFICATE_BUNDLE", "sourceData": {"x509CertificateData": ca_pem}},
        tags=[{"key": "sim2real-check", "value": CHECK}],
    )["trustAnchor"]
    ta_id = created["trustAnchorId"]
    ctx.on_cleanup(lambda: ra.delete_trust_anchor(trustAnchorId=ta_id))

    before = ra.get_trust_anchor(trustAnchorId=ta_id)["trustAnchor"]
    default_entry = _find_setting(before["notificationSettings"], "CA_CERTIFICATE_EXPIRY", "ALL")
    assert default_entry is not None, "fresh trust anchor has no CA_CERTIFICATE_EXPIRY/ALL setting"
    assert default_entry["configuredBy"] == "rolesanywhere.amazonaws.com", (
        f"expected default configuredBy=rolesanywhere.amazonaws.com, got {default_entry['configuredBy']!r}"
    )
    assert default_entry["threshold"] == 45, f"expected default threshold=45, got {default_entry['threshold']!r}"
    assert default_entry["enabled"] is True, f"expected default enabled=True, got {default_entry['enabled']!r}"

    ra.put_notification_settings(
        trustAnchorId=ta_id,
        notificationSettings=[
            {"event": "CA_CERTIFICATE_EXPIRY", "channel": "ALL", "enabled": True, "threshold": 100}
        ],
    )
    after_put = ra.get_trust_anchor(trustAnchorId=ta_id)["trustAnchor"]
    put_entry = _find_setting(after_put["notificationSettings"], "CA_CERTIFICATE_EXPIRY", "ALL")
    assert put_entry is not None, "CA_CERTIFICATE_EXPIRY/ALL setting vanished after PutNotificationSettings"
    assert put_entry["configuredBy"] == account_id, (
        f"expected configuredBy={account_id!r} after PutNotificationSettings, got {put_entry['configuredBy']!r}"
    )
    assert put_entry["threshold"] == 100, f"expected threshold=100 after override, got {put_entry['threshold']!r}"

    ra.reset_notification_settings(
        trustAnchorId=ta_id,
        notificationSettingKeys=[{"event": "CA_CERTIFICATE_EXPIRY", "channel": "ALL"}],
    )
    after_reset = ra.get_trust_anchor(trustAnchorId=ta_id)["trustAnchor"]
    reset_entry = _find_setting(after_reset["notificationSettings"], "CA_CERTIFICATE_EXPIRY", "ALL")
    assert reset_entry is not None, "CA_CERTIFICATE_EXPIRY/ALL setting vanished after ResetNotificationSettings"
    assert reset_entry["configuredBy"] == "rolesanywhere.amazonaws.com", (
        f"expected configuredBy reverted to rolesanywhere.amazonaws.com, got {reset_entry['configuredBy']!r}"
    )
    assert reset_entry["threshold"] == 45, f"expected threshold reverted to 45, got {reset_entry['threshold']!r}"


def _generate_ca_pem(common_name: str) -> str:
    import datetime

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    now = datetime.datetime.utcnow()
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=2))
        .add_extension(x509.BasicConstraints(ca=True, path_length=1), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=False,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.PEM).decode("ascii")


def _find_setting(settings, event: str, channel: str):
    for entry in settings:
        if entry.get("event") == event and entry.get("channel") == channel:
            return entry
    return None


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
