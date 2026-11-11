"""update-security-config-optimistic-lock-stale-version-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-security-config-optimistic-lock-stale-version-rejected"
GROUP = "concurrency"
SERVICES = ["opensearchserverless"]

_MALFORMED_VERSION_MESSAGE = (
    "1 validation error detected: Value 'not-a-valid-version-token!!' at 'configVersion' failed to "
    "satisfy constraint: Member must satisfy regular expression pattern: "
    "([0-9a-zA-Z+/]{4})*(([0-9a-zA-Z+/]{2}==)|([0-9a-zA-Z+/]{3}=))?"
)
_STALE_VERSION_MESSAGE = (
    "Policy version specified in the request refers to an older version and policy has since changed"
)

_DUMMY_CERT = (
    "MIICWzCCAcQCCQCS+ysu4d5PGDANBgkqhkiG9w0BAQsFADBqMQswCQYDVQQGEwJVUzELMAkGA1UE"
    "CAwCV0ExEDAOBgNVBAcMB1NlYXR0bGUxDzANBgNVBAoMBnNpbTJyZTEQMA4GA1UECwwHc2ltMnJl"
    "MRcwFQYDVQQDDA5zaW0ycmVhbC5sb2NhbDAeFw0yNDAxMDEwMDAwMDBaFw0zNDAxMDEwMDAwMDBa"
    "MGoxCzAJBgNVBAYTAlVTMQswCQYDVQQIDAJXQTEQMA4GA1UEBwwHU2VhdHRsZTEPMA0GA1UECgwG"
    "c2ltMnJlMRAwDgYDVQQLDAdzaW0ycmUxFzAVBgNVBAMMDnNpbTJyZWFsLmxvY2FsMIGfMA0GCSqG"
    "SIb3DQEBAQUAA4GNADCBiQKBgQC7VJTUt9Us8cKjMzEfYyjiWA4R4/M2bS1GB4t7NXp98C3SC6dV"
    "MvDuictGeurT8jNbvJZHtCSuYEvuNMoSfm76oqFvAp8Gy0iz5sxjZmSnXyCdPEovGhLa0VzMaQ8s"
    "+CLOyS56YyCFGeJZqgtzJ6GR3eqoYSW9b9UMvkBpZODSctWSNGj3P7jRFDO5VoTwCQAWbFnOjDfH"
    "5UlgxKMwAgMBAAEwDQYJKoZIhvcNAQELBQADgYEAjq7HKVMj+9pQTn9tzTVaBFsCd+PMCbY8jNs="
)
_SAML_METADATA = (
    '<?xml version="1.0"?>'
    '<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" '
    'entityID="https://sim2real.example.com/saml">'
    '<IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">'
    '<KeyDescriptor use="signing">'
    '<KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#">'
    "<X509Data>"
    f"<X509Certificate>{_DUMMY_CERT}</X509Certificate>"
    "</X509Data>"
    "</KeyInfo>"
    "</KeyDescriptor>"
    '<SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" '
    'Location="https://sim2real.example.com/saml/sso"/>'
    "</IDPSSODescriptor></EntityDescriptor>"
)


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """UpdateSecurityConfig rejects a stale/malformed configVersion with ValidationException."""
    client = ctx.client("opensearchserverless")
    name = ctx.unique_name("sim2real-scv-")

    created = client.create_security_config(
        type="saml",
        name=name,
        samlOptions={"metadata": _SAML_METADATA},
    )["securityConfigDetail"]
    config_id = created["id"]
    ctx.on_cleanup(lambda: client.delete_security_config(id=config_id))
    base_version = created["configVersion"]

    # Overly-permissive boundary: a malformed configVersion (wrong length/pattern) is rejected.
    code, message = _error(
        lambda: client.update_security_config(
            id=config_id,
            configVersion="not-a-valid-version-token!!",
            description="should-not-apply",
        )
    )
    assert code == "ValidationException", (
        f"expected ValidationException for a malformed configVersion, got {code!r}"
    )
    assert message == _MALFORMED_VERSION_MESSAGE, (
        f"expected message {_MALFORMED_VERSION_MESSAGE!r}, got {message!r}"
    )

    v1 = client.update_security_config(
        id=config_id,
        configVersion=base_version,
        description="updated-once",
        samlOptions={"metadata": _SAML_METADATA, "sessionTimeout": 90},
    )["securityConfigDetail"]
    current_version = v1["configVersion"]
    assert current_version != base_version, "configVersion should change after a successful update"

    # Break exactly one thing: reuse the now-stale (already-consumed) base_version.
    code, message = _error(
        lambda: client.update_security_config(
            id=config_id,
            configVersion=base_version,
            description="updated-with-stale-version",
            samlOptions={"metadata": _SAML_METADATA, "sessionTimeout": 180},
        )
    )
    assert code == "ValidationException", (
        f"expected ValidationException for a stale (already-consumed) configVersion, got {code!r}"
    )
    assert message == _STALE_VERSION_MESSAGE, (
        f"expected message {_STALE_VERSION_MESSAGE!r}, got {message!r}"
    )

    # Effect must be absent: the rejected call's description never persisted.
    got = client.get_security_config(id=config_id)["securityConfigDetail"]
    assert got["description"] == "updated-once", (
        f"expected the stale-version update to leave description as 'updated-once', got {got['description']!r}"
    )
    assert got["configVersion"] == current_version, (
        f"expected the stale-version update to leave configVersion as {current_version!r}, "
        f"got {got['configVersion']!r}"
    )

    # Positive control: the correct (current) version is still accepted (change the
    # samlOptions content again so the version is guaranteed to mint anew).
    final = client.update_security_config(
        id=config_id,
        configVersion=current_version,
        description="updated-twice",
        samlOptions={"metadata": _SAML_METADATA, "sessionTimeout": 240},
    )["securityConfigDetail"]
    assert final["description"] == "updated-twice", (
        f"expected the restored-version update to succeed with description 'updated-twice', "
        f"got {final['description']!r}"
    )
    assert final["configVersion"] != current_version, (
        f"expected a successful update to mint a new configVersion distinct from {current_version!r}"
    )

    # Terminal read: independent of the mutating call, at the destination.
    got_final = client.get_security_config(id=config_id)["securityConfigDetail"]
    assert got_final["description"] == "updated-twice", (
        f"expected the persisted description to be 'updated-twice', got {got_final['description']!r}"
    )
    assert got_final["configVersion"] == final["configVersion"], (
        f"expected the persisted configVersion to be {final['configVersion']!r}, "
        f"got {got_final['configVersion']!r}"
    )


def _error(fn):
    """Call fn(); return its botocore error code and message. An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as err:
        error = err.response["Error"]
        return error["Code"], error.get("Message", "")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
