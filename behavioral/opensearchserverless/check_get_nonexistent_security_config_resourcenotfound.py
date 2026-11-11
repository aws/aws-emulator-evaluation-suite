"""get-nonexistent-security-config-resourcenotfound."""
from __future__ import annotations

import re
from typing import Any, Callable

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "get-nonexistent-security-config-resourcenotfound"
GROUP = "error-semantics"
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

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetSecurityConfig for an unknown config id returns ResourceNotFoundException rather than
    an empty/default payload, while a real security config remains fully gettable (positive
    control)."""
    aoss = ctx.client("opensearchserverless")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]
    # A well-formed id (saml/<real-account-id>/<provider>) that was never created, so the
    # account-id segment can't itself trigger a cross-account validation error -- only the
    # nonexistence of the provider is being probed.
    fake_config_id = f"saml/{account_id}/sim2real-behav-definitely-not-a-real-provider"
    name = _short_name(ctx, "sim2real-getsc")

    created = aoss.create_security_config(
        type="saml", name=name, samlOptions={"metadata": _SAML_METADATA}
    )["securityConfigDetail"]
    config_id = created["id"]

    def _cleanup() -> None:
        try:
            aoss.delete_security_config(id=config_id)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise

    ctx.on_cleanup(_cleanup)

    # negative: an id that was never created is rejected with ResourceNotFoundException
    code, message = _error(lambda: aoss.get_security_config(id=fake_config_id))
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code!r}"
    expected_message = f"Security config with id: {fake_config_id} does not exist"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # positive control: the real security config is unaffected and still gettable
    got = aoss.get_security_config(id=config_id)["securityConfigDetail"]
    assert got["id"] == config_id, f"expected id {config_id!r}, got {got['id']!r}"
    assert got["configVersion"] == created["configVersion"], (
        f"expected configVersion {created['configVersion']!r}, got {got['configVersion']!r}"
    )


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
