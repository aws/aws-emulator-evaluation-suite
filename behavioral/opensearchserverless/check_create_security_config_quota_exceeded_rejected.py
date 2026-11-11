"""create-security-config-quota-exceeded-rejected."""
from __future__ import annotations

import re
from typing import Any, Callable

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "create-security-config-quota-exceeded-rejected"
GROUP = "error-semantics"
SERVICES = ["opensearchserverless"]

# Default, non-adjustable account quota for SAML providers (see the "OpenSearch Serverless
# quotas" table at https://docs.aws.amazon.com/general/latest/gr/opensearch-service.html).
_SAML_PROVIDER_QUOTA = 50

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
    """SAML security configs up to the fixed quota of 50 are created and listed, the next fails with
    ServiceQuotaExceededException and its exact message and is not stored, and after one is deleted the
    same call succeeds.
    """
    aoss = ctx.client("opensearchserverless")

    existing = _list_all_saml_config_ids(aoss)
    to_create = max(0, _SAML_PROVIDER_QUOTA - len(existing))

    created_ids: list[str] = []

    def _cleanup() -> None:
        for cid in created_ids:
            try:
                aoss.delete_security_config(id=cid)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                    raise

    ctx.on_cleanup(_cleanup)

    for i in range(to_create):
        name = _short_name(ctx, f"sim2real-scq{i}")
        resp = aoss.create_security_config(
            type="saml", name=name, samlOptions={"metadata": _SAML_METADATA}
        )["securityConfigDetail"]
        created_ids.append(resp["id"])

    # positive control: creation genuinely worked, not a no-op -- fetch one back
    if created_ids:
        got = aoss.get_security_config(id=created_ids[0])["securityConfigDetail"]
        assert got["id"] == created_ids[0], (
            f"expected independent get_security_config to return {created_ids[0]!r}, got {got!r}"
        )

    listed_now = set(_list_all_saml_config_ids(aoss))
    missing = sorted(set(created_ids) - listed_now)
    assert not missing, f"expected every config this check created to be listed, missing {missing}"

    # negative: the next create is rejected once the account is at quota
    over_name = _short_name(ctx, "sim2real-scq-over")
    code, message = _error(
        lambda: aoss.create_security_config(
            type="saml", name=over_name, samlOptions={"metadata": _SAML_METADATA}
        )
    )
    assert code == "ServiceQuotaExceededException", (
        f"expected ServiceQuotaExceededException at quota, got {code!r}"
    )
    expected = (
        "Your request exceeds the limit for saml policies in this AWS account. "
        f"The limit is {_SAML_PROVIDER_QUOTA}."
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # effect absent: the rejected config was never persisted
    over_id = f"saml/{ctx.account}/{over_name}"
    assert over_id not in _list_all_saml_config_ids(aoss), (
        f"the rejected config {over_id!r} was persisted anyway"
    )

    # restore: free exactly one slot, then the identical call must now succeed -- this is what
    # separates "blocked because the account is at its quota" from "blocked for any reason"
    freed_id = created_ids.pop()
    aoss.delete_security_config(id=freed_id)

    restored = aoss.create_security_config(
        type="saml", name=over_name, samlOptions={"metadata": _SAML_METADATA}
    )["securityConfigDetail"]
    created_ids.append(restored["id"])

    got_restored = aoss.get_security_config(id=restored["id"])["securityConfigDetail"]
    assert got_restored["id"] == restored["id"], (
        f"expected independent get_security_config to return {restored['id']!r} after "
        f"restoring, got {got_restored!r}"
    )

    assert restored["id"] == over_id, f"expected the restored id {over_id!r}, got {restored['id']!r}"
    listed_after = set(_list_all_saml_config_ids(aoss))
    assert freed_id not in listed_after, f"the freed config {freed_id!r} is still listed"
    assert over_id in listed_after, f"the restored config {over_id!r} is not listed"


def _short_name(ctx: Any, prefix: str) -> str:
    raw = ctx.unique_name(prefix + "-").lower()
    raw = re.sub(r"[^a-z0-9-]", "", raw)
    if not raw or not raw[0].isalpha():
        raw = "a" + raw
    raw = raw[:32].rstrip("-")
    while len(raw) < 3:
        raw += "0"
    return raw


def _list_all_saml_config_ids(aoss) -> list[str]:
    ids: list[str] = []
    next_token = None
    while True:
        kwargs: dict[str, Any] = {"type": "saml", "maxResults": 100}
        if next_token:
            kwargs["nextToken"] = next_token
        resp = aoss.list_security_configs(**kwargs)
        ids.extend(s["id"] for s in resp.get("securityConfigSummaries", []))
        next_token = resp.get("nextToken")
        if not next_token:
            return ids


def _error(fn: Callable[[], Any]) -> tuple[str, str]:
    """The (code, message) of the AWS error ``fn`` raises; a call that succeeds fails the check."""
    try:
        result = fn()
    except Exception as exc:
        response = getattr(exc, "response", None)
        if response is None:
            raise
        return response["Error"]["Code"], response["Error"].get("Message", "")
    raise AssertionError(
        f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
