"""signing-configuration-round-trip."""
from __future__ import annotations

import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "signing-configuration-round-trip"
GROUP = "data-plane"
SERVICES = ["ecr"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:ecr-signing-configuration")
def run(ctx) -> None:
    """A PutSigningConfiguration payload of signing profile ARNs and repository filters
    round-trips unchanged through GetSigningConfiguration."""
    ecr = ctx.client("ecr")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]
    repo_prefix = ctx.unique_name("sim2real-ecr-signrt-")

    original = None
    try:
        original = ecr.get_signing_configuration()["signingConfiguration"]
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "SigningConfigurationNotFoundException":
            raise

    def _restore():
        if original is None:
            try:
                ecr.delete_signing_configuration()
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "SigningConfigurationNotFoundException":
                    raise
        else:
            ecr.put_signing_configuration(signingConfiguration=original)

    ctx.on_cleanup(_restore)

    profile_name = "Sim2RealRoundTripProfile_" + uuid.uuid4().hex
    profile_arn = f"arn:aws:signer:{ctx.region}:{account_id}:/signing-profiles/{profile_name}"
    payload = {
        "rules": [{
            "signingProfileArn": profile_arn,
            "repositoryFilters": [{"filter": f"{repo_prefix}*", "filterType": "WILDCARD_MATCH"}],
        }],
    }

    put_resp = ecr.put_signing_configuration(signingConfiguration=payload)
    assert put_resp["signingConfiguration"] == payload, (
        f"PutSigningConfiguration echo mismatch: expected {payload!r}, "
        f"got {put_resp['signingConfiguration']!r}"
    )

    get_resp = ecr.get_signing_configuration()
    assert get_resp["signingConfiguration"] == payload, (
        f"GetSigningConfiguration mismatch: expected {payload!r}, "
        f"got {get_resp['signingConfiguration']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
