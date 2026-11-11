"""security-configuration-create-describe-list-delete."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "security-configuration-create-describe-list-delete"
GROUP = "state"
SERVICES = ["emr-containers"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateSecurityConfiguration persists securityConfigurationData verbatim, the
    configuration shows up in ListSecurityConfigurations, and after
    DeleteSecurityConfiguration it is gone (ResourceNotFoundException on describe)."""
    emrc = ctx.client("emr-containers")
    name = ctx.unique_name("sim2real-sc-")
    data = {
        "authorizationConfiguration": {
            "encryptionConfiguration": {
                "inTransitEncryptionConfiguration": {
                    "tlsCertificateConfiguration": {
                        "certificateProviderType": "PEM",
                        "publicCertificateSecretArn": (
                            "arn:aws:secretsmanager:us-east-1:123456789012:secret:pub-abc123"
                        ),
                        "privateCertificateSecretArn": (
                            "arn:aws:secretsmanager:us-east-1:123456789012:secret:priv-abc123"
                        ),
                    }
                }
            },
            # The real service rejects authorizationConfiguration without a
            # fully populated lakeFormationConfiguration sibling, despite the
            # public API docs marking every one of these fields optional --
            # empirically required in practice.
            "lakeFormationConfiguration": {
                "authorizedSessionTagValue": "sim2real-lf-tag",
                "queryEngineRoleArn": "arn:aws:iam::123456789012:role/sim2real-query-engine-role",
                "secureNamespaceInfo": {
                    "clusterId": "sim2real-cluster-id",
                    "namespace": "sim2real-namespace",
                },
            },
        }
    }

    created = emrc.create_security_configuration(
        clientToken=ctx.unique_name("tok-"), name=name, securityConfigurationData=data
    )
    config_id = created["id"]
    ctx.on_cleanup(lambda: _delete_ignore_not_found(emrc, config_id))

    described = emrc.describe_security_configuration(id=config_id)["securityConfiguration"]
    assert described["name"] == name, f"expected name {name!r}, got {described['name']!r}"
    auth_config = described["securityConfigurationData"]["authorizationConfiguration"]
    tls = auth_config["encryptionConfiguration"]["inTransitEncryptionConfiguration"][
        "tlsCertificateConfiguration"
    ]
    assert tls["certificateProviderType"] == "PEM", (
        f"expected certificateProviderType PEM, got {tls['certificateProviderType']!r}"
    )
    assert tls["publicCertificateSecretArn"].endswith("pub-abc123"), (
        f"expected publicCertificateSecretArn ending pub-abc123, got "
        f"{tls['publicCertificateSecretArn']!r}"
    )
    assert tls["privateCertificateSecretArn"].endswith("priv-abc123"), (
        f"expected privateCertificateSecretArn ending priv-abc123, got "
        f"{tls['privateCertificateSecretArn']!r}"
    )
    lf_config = auth_config["lakeFormationConfiguration"]
    assert lf_config["authorizedSessionTagValue"] == "sim2real-lf-tag", (
        f"expected authorizedSessionTagValue sim2real-lf-tag, got "
        f"{lf_config['authorizedSessionTagValue']!r}"
    )
    assert lf_config["queryEngineRoleArn"].endswith("sim2real-query-engine-role"), (
        f"expected queryEngineRoleArn ending sim2real-query-engine-role, got "
        f"{lf_config['queryEngineRoleArn']!r}"
    )
    secure_ns = lf_config["secureNamespaceInfo"]
    assert secure_ns == {"clusterId": "sim2real-cluster-id", "namespace": "sim2real-namespace"}, (
        f"expected secureNamespaceInfo to round-trip verbatim, got {secure_ns!r}"
    )

    listed = emrc.list_security_configurations()["securityConfigurations"]
    assert any(c["id"] == config_id for c in listed), (
        f"expected {config_id!r} in ListSecurityConfigurations, got ids "
        f"{[c['id'] for c in listed]!r}"
    )

    emrc.delete_security_configuration(id=config_id)

    code, message = _client_error(lambda: emrc.describe_security_configuration(id=config_id))
    assert code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException on describe after delete, got {code!r}"
    )
    expected = f"Security Configuration {config_id} doesn't exist."
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # A mutation on the dead id must also fail, not just a read.
    redelete_code, redelete_message = _client_error(
        lambda: emrc.delete_security_configuration(id=config_id)
    )
    assert redelete_code == "ValidationException", (
        f"expected ValidationException on re-delete of {config_id!r}, got {redelete_code!r}"
    )
    expected = "Security configuration not found"
    assert redelete_message == expected, (
        f"expected message {expected!r}, got {redelete_message!r}"
    )


def _delete_ignore_not_found(emrc, config_id: str) -> None:
    from botocore.exceptions import ClientError

    try:
        emrc.delete_security_configuration(id=config_id)
    except ClientError as err:
        # A security configuration already deleted in the run is refused with exactly this error.
        error = err.response["Error"]
        if (error["Code"], error.get("Message")) != (
            "ValidationException", "Security configuration not found"
        ):
            raise


def _client_error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected success raises, so an
    accepted call that AWS refuses fails as accepted, not as an error mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")

if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
