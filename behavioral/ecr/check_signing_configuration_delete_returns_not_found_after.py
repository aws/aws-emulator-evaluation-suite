"""signing-configuration-delete-returns-not-found-after."""
from __future__ import annotations

import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "signing-configuration-delete-returns-not-found-after"
GROUP = "state-machine"
SERVICES = ["ecr"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:ecr-signing-configuration")
def run(ctx) -> None:
    """A signing configuration put is read back with its profile ARN, and after
    DeleteSigningConfiguration GetSigningConfiguration is refused
    SigningConfigurationNotFoundException with the exact message."""
    ecr = ctx.client("ecr")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    original = _get_signing_configuration_or_none(ecr)
    ctx.on_cleanup(lambda: _restore_signing_configuration(ctx, original))

    profile_name = "sim2real" + uuid.uuid4().hex[:12]
    signing_profile_arn = f"arn:aws:signer:{ctx.region}:{account_id}:/signing-profiles/{profile_name}"
    signing_configuration = {
        "rules": [
            {
                "signingProfileArn": signing_profile_arn,
                "repositoryFilters": [{"filter": "*", "filterType": "WILDCARD_MATCH"}],
            }
        ]
    }
    ecr.put_signing_configuration(signingConfiguration=signing_configuration)

    fetched = ecr.get_signing_configuration()
    fetched_arn = fetched["signingConfiguration"]["rules"][0]["signingProfileArn"]
    assert fetched_arn == signing_profile_arn, (
        f"expected the put signing profile arn {signing_profile_arn!r} to round-trip, got {fetched_arn!r}"
    )

    ecr.delete_signing_configuration()

    code, message = _client_error(lambda: ecr.get_signing_configuration())
    assert code == "SigningConfigurationNotFoundException", (
        f"expected GetSigningConfiguration to fail with SigningConfigurationNotFoundException "
        f"after delete, got {code!r}"
    )
    assert message == (
        f"The signing configuration does not exist in the registry with id '{account_id}'"
    ), message


def _client_error(fn):
    """Call fn(); return its (error code, error message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _get_signing_configuration_or_none(ecr):
    try:
        return ecr.get_signing_configuration()["signingConfiguration"]
    except ClientError as err:
        if err.response["Error"]["Code"] == "SigningConfigurationNotFoundException":
            return None
        raise


def _restore_signing_configuration(ctx, original) -> None:
    ecr = ctx.client("ecr")
    if original is None:
        try:
            ecr.delete_signing_configuration()
        except ClientError as err:
            if err.response["Error"]["Code"] != "SigningConfigurationNotFoundException":
                raise
    else:
        ecr.put_signing_configuration(signingConfiguration=original)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
