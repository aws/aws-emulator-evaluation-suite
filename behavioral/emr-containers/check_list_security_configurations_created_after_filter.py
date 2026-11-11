"""list-security-configurations-created-after-filter."""
from __future__ import annotations

import datetime

from behavioral_harness import tags

CHECK = "list-security-configurations-created-after-filter"
GROUP = "data-plane"
SERVICES = ["emr-containers"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListSecurityConfigurations honors the createdAfter filter: a cutoff placed
    after creation excludes the new configuration, one placed before it includes it."""
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
    before_create = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(minutes=1)

    created = emrc.create_security_configuration(
        clientToken=ctx.unique_name("tok-"), name=name, securityConfigurationData=data
    )
    config_id = created["id"]
    ctx.on_cleanup(lambda: _delete_ignore_not_found(emrc, config_id))

    after_create = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(minutes=1)

    included = emrc.list_security_configurations(createdAfter=before_create)[
        "securityConfigurations"
    ]
    included_ids = [c["id"] for c in included]
    assert config_id in included_ids, (
        f"expected {config_id!r} in ListSecurityConfigurations with "
        f"createdAfter={before_create.isoformat()!r} (before creation), got ids {included_ids!r}"
    )

    excluded = emrc.list_security_configurations(createdAfter=after_create)[
        "securityConfigurations"
    ]
    excluded_ids = [c["id"] for c in excluded]
    assert config_id not in excluded_ids, (
        f"expected {config_id!r} excluded from ListSecurityConfigurations with "
        f"createdAfter={after_create.isoformat()!r} (after creation), got ids {excluded_ids!r}"
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


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
