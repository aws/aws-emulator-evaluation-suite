"""signing-configuration-rule-set-round-trip."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "signing-configuration-rule-set-round-trip"
GROUP = "representation"
SERVICES = ["ecr"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:ecr-signing-configuration")
def run(ctx) -> None:
    """A signing configuration with multiple rules, each carrying its own signing
    profile ARN and multiple repository filters, persists with exact field values
    and list ordering across PutSigningConfiguration/GetSigningConfiguration."""
    ecr = ctx.client("ecr")
    signer = ctx.client("signer")

    profile_names = [ctx.unique_name(f"sim2real_ecr_sig_{i}_").replace("-", "_") for i in range(2)]
    profile_arns = []
    for name in profile_names:
        resp = signer.put_signing_profile(profileName=name, platformId="Notation-OCI-SHA384-ECDSA")
        ctx.on_cleanup(lambda n=name: signer.cancel_signing_profile(profileName=n))
        profile_arns.append(resp["arn"])

    original_config, had_config = _get_signing_configuration(ecr)

    def _restore():
        if had_config:
            ecr.put_signing_configuration(signingConfiguration=original_config)
        else:
            try:
                ecr.delete_signing_configuration()
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "SigningConfigurationNotFoundException":
                    raise

    ctx.on_cleanup(_restore)

    rules = [
        {
            "signingProfileArn": profile_arns[0],
            "repositoryFilters": [
                {"filter": "team-a/*", "filterType": "WILDCARD_MATCH"},
                {"filter": "*-production", "filterType": "WILDCARD_MATCH"},
            ],
        },
        {
            "signingProfileArn": profile_arns[1],
            "repositoryFilters": [{"filter": "team-b/*staging*", "filterType": "WILDCARD_MATCH"}],
        },
    ]
    ecr.put_signing_configuration(signingConfiguration={"rules": rules})
    fetched = ecr.get_signing_configuration()["signingConfiguration"]["rules"]

    assert len(fetched) == 2, f"expected 2 rules preserved in order, got {fetched!r}"
    for expected, actual in zip(rules, fetched):
        assert actual["signingProfileArn"] == expected["signingProfileArn"], (
            f"expected signingProfileArn {expected['signingProfileArn']!r}, got {actual['signingProfileArn']!r}"
        )
        assert actual["repositoryFilters"] == expected["repositoryFilters"], (
            f"expected repositoryFilters {expected['repositoryFilters']!r}, got {actual['repositoryFilters']!r}"
        )


# ===== helpers =====
def _get_signing_configuration(ecr):
    try:
        return ecr.get_signing_configuration()["signingConfiguration"], True
    except ClientError as e:
        if e.response["Error"]["Code"] == "SigningConfigurationNotFoundException":
            return None, False
        raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
