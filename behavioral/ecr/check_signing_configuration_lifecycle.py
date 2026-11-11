"""signing-configuration-lifecycle."""
from __future__ import annotations

import re

from behavioral_harness import tags

CHECK = "signing-configuration-lifecycle"
GROUP = "state-machine"
SERVICES = ["ecr"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:ecr-signing-configuration")
def run(ctx) -> None:
    """PutSigningConfiguration creates a registry-wide signing config, GetSigningConfiguration
    returns the persisted rule, and DeleteSigningConfiguration tears it down so a subsequent
    Get raises SigningConfigurationNotFoundException."""
    ecr = ctx.client("ecr")
    account_id = ctx.client("sts").get_caller_identity()["Account"]

    profile_name = _alnum(ctx.unique_name("sim2realsignprofile"))
    signing_profile_arn = (
        f"arn:aws:signer:{ctx.region}:{account_id}:/signing-profiles/{profile_name}"
    )
    repo_filter_value = _alnum(ctx.unique_name("sim2real")).lower() + "*"

    # Snapshot any pre-existing registry signing configuration so we can restore it, since
    # Put/Delete operate on the single registry-wide config (overwrite semantics).
    original = _get_signing_configuration_or_none(ecr)

    def _restore() -> None:
        if original is not None:
            ecr.put_signing_configuration(signingConfiguration=original)
        else:
            _delete_signing_configuration_or_ignore(ecr)

    ctx.on_cleanup(_restore)

    put_resp = ecr.put_signing_configuration(
        signingConfiguration={
            "rules": [
                {
                    "signingProfileArn": signing_profile_arn,
                    "repositoryFilters": [
                        {"filter": repo_filter_value, "filterType": "WILDCARD_MATCH"}
                    ],
                }
            ]
        }
    )
    put_arn = put_resp["signingConfiguration"]["rules"][0]["signingProfileArn"]
    assert put_arn == signing_profile_arn, (
        f"expected PutSigningConfiguration to echo signingProfileArn={signing_profile_arn!r}, "
        f"got {put_arn!r}"
    )

    get_resp = ecr.get_signing_configuration()
    rules = get_resp["signingConfiguration"]["rules"]
    matching = [r for r in rules if r["signingProfileArn"] == signing_profile_arn]
    assert len(matching) == 1, (
        f"expected exactly one persisted rule for signingProfileArn={signing_profile_arn!r} "
        f"via an independent GetSigningConfiguration, found {len(matching)} in {rules!r}"
    )
    persisted_filter = matching[0]["repositoryFilters"][0]["filter"]
    assert persisted_filter == repo_filter_value, (
        f"expected persisted repositoryFilters[0].filter={repo_filter_value!r}, "
        f"got {persisted_filter!r}"
    )

    ecr.delete_signing_configuration()

    code, message = _client_error(lambda: ecr.get_signing_configuration())
    assert code == "SigningConfigurationNotFoundException", (
        "expected GetSigningConfiguration to raise SigningConfigurationNotFoundException "
        f"after DeleteSigningConfiguration, got {code!r}"
    )
    assert message == (
        f"The signing configuration does not exist in the registry with id '{ctx.account}'"
    ), message


def _alnum(s: str) -> str:
    return re.sub(r"[^a-zA-Z0-9_]", "_", s)


def _client_error(fn):
    """Call fn(); return its (error code, error message). An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _get_signing_configuration_or_none(ecr):
    from botocore.exceptions import ClientError

    try:
        return ecr.get_signing_configuration()["signingConfiguration"]
    except ClientError as err:
        if err.response["Error"]["Code"] == "SigningConfigurationNotFoundException":
            return None
        raise


def _delete_signing_configuration_or_ignore(ecr) -> None:
    from botocore.exceptions import ClientError

    try:
        ecr.delete_signing_configuration()
    except ClientError as err:
        if err.response["Error"]["Code"] != "SigningConfigurationNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
