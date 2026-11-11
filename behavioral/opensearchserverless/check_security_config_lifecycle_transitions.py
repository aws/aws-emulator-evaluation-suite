"""security-config-lifecycle-transitions."""
from __future__ import annotations

import re
from typing import Any, Callable

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "security-config-lifecycle-transitions"
GROUP = "state-machine"
SERVICES = ["opensearchserverless"]

_SAML_METADATA = (
    '<?xml version="1.0"?>'
    '<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" '
    'entityID="https://sim2real.example.com/saml/metadata">'
    '<IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">'
    '<KeyDescriptor use="signing"><KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#">'
    '<X509Data><X509Certificate>MIIBozCCAWACAQEwDQYJKoZIhvcNAQEFBQAwYzELMAkGA1UE'
    "BhMCVVMxCzAJBgNVBAgTAldBMRAwDgYDVQQHEwdTZWF0dGxlMQ8wDQYDVQQKEwZBbWF6b24xFDAS"
    'BgNVBAsTC0lBTSBDb25zb2xlMBoXDTAgMTAxMDA=</X509Certificate></X509Data></KeyInfo>'
    "</KeyDescriptor>"
    '<SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" '
    'Location="https://sim2real.example.com/saml/sso"/>'
    "</IDPSSODescriptor></EntityDescriptor>"
)


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """SecurityConfig created, fetched, updated in place, then deleted leaving Get 404."""
    aoss = ctx.client("opensearchserverless")
    name = _short_name(ctx, "sim2real-sconf")

    created = aoss.create_security_config(
        type="saml",
        name=name,
        description="sim2real behavioral security config",
        samlOptions={"metadata": _SAML_METADATA},
    )["securityConfigDetail"]
    config_id = created["id"]
    version1 = created["configVersion"]
    assert created["type"] == "saml", f"expected type saml, got {created['type']!r}"
    assert created["description"] == "sim2real behavioral security config", (
        f"expected the create-time description to round-trip, got {created['description']!r}"
    )

    def _cleanup() -> None:
        try:
            aoss.delete_security_config(id=config_id)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise

    ctx.on_cleanup(_cleanup)

    got = aoss.get_security_config(id=config_id)["securityConfigDetail"]
    assert got["id"] == config_id, f"expected GetSecurityConfig to return {config_id!r}, got {got['id']!r}"
    assert got["configVersion"] == version1, (
        f"expected an unmodified read to keep configVersion {version1!r}, got {got['configVersion']!r}"
    )

    updated = aoss.update_security_config(
        id=config_id,
        configVersion=version1,
        description="sim2real behavioral security config v2",
        samlOptions={"metadata": _SAML_METADATA, "sessionTimeout": 120},
    )["securityConfigDetail"]
    assert updated["description"] == "sim2real behavioral security config v2", (
        f"expected the updated description to round-trip, got {updated['description']!r}"
    )
    assert updated["samlOptions"]["sessionTimeout"] == 120, (
        f"expected sessionTimeout 120 to round-trip, got {updated['samlOptions'].get('sessionTimeout')!r}"
    )
    assert updated["configVersion"] != version1, (
        f"expected configVersion to advance past {version1!r} after a successful update, "
        f"got the same value back"
    )

    got2 = aoss.get_security_config(id=config_id)["securityConfigDetail"]
    assert got2["description"] == "sim2real behavioral security config v2", (
        f"expected a post-update read to see the new description, got {got2['description']!r}"
    )
    assert got2["configVersion"] == updated["configVersion"], (
        f"expected a post-update read to see configVersion {updated['configVersion']!r}, "
        f"got {got2['configVersion']!r}"
    )

    aoss.delete_security_config(id=config_id)

    code, message = _error(lambda: aoss.get_security_config(id=config_id))
    assert code == "ResourceNotFoundException", (
        f"expected GetSecurityConfig on a deleted id to fail with ResourceNotFoundException, got {code!r}"
    )
    expected_message = f"Security config with id: {config_id} does not exist"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"


def _short_name(ctx: Any, prefix: str) -> str:
    raw = ctx.unique_name(prefix + "-").lower()
    raw = re.sub(r"[^a-z0-9-]", "", raw)
    if not raw or not raw[0].isalpha():
        raw = "a" + raw
    raw = raw[:32].rstrip("-")
    while len(raw) < 3:
        raw += "0"
    return raw


def _error(fn: Callable[[], Any]) -> tuple[str, str]:
    """(code, message) of the error ``fn`` raises. An unexpected success raises AssertionError, so a
    target that accepts what AWS refuses fails loudly instead of reading as a code mismatch."""
    try:
        result = fn()
    except Exception as exc:
        response = getattr(exc, "response", None)
        if response is None:
            raise
        return response["Error"]["Code"], response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
