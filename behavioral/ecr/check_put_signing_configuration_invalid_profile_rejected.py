"""put-signing-configuration-invalid-profile-rejected."""
from __future__ import annotations

import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-signing-configuration-invalid-profile-rejected"
GROUP = "error-semantics"
SERVICES = ["ecr"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:ecr-signing-configuration")
def run(ctx) -> None:
    """PutSigningConfiguration with a malformed signing-profile ARN (fails the documented
    Pattern constraint) returns InvalidParameterException and never persists anything, while
    a syntactically well-formed ARN is accepted (positive control)."""
    ecr = ctx.client("ecr")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    original = _snapshot_signing_configuration(ecr)
    ctx.on_cleanup(lambda: _restore_signing_configuration(ecr, original))
    if original is not None:
        ecr.delete_signing_configuration()

    bad_config = {"rules": [{"signingProfileArn": "not-a-valid-signer-profile-arn"}]}
    code, message = _client_error(lambda: ecr.put_signing_configuration(signingConfiguration=bad_config))
    # Real AWS rejects the malformed ARN with InvalidParameterException (empirically
    # observed), not the more generic ValidationException.
    assert code == "InvalidParameterException", code
    expected = (
        "Invalid parameter at 'signingProfileArn' failed to satisfy constraint: "
        f"'The signing profile ARN '{bad_config['rules'][0]['signingProfileArn']}' must be well formed'"
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Effect absent: no signing configuration was persisted.
    code2, message2 = _client_error(lambda: ecr.get_signing_configuration())
    assert code2 == "SigningConfigurationNotFoundException", code2
    expected2 = (
        f"The signing configuration does not exist in the registry with id '{account_id}'"
    )
    assert message2 == expected2, f"expected message {expected2!r}, got {message2!r}"

    # Positive control: a well-formed signing profile ARN is accepted.
    profile_name = "sim2realsp" + uuid.uuid4().hex[:12]
    good_config = _valid_signing_configuration(account_id, ctx.region, profile_name)
    ecr.put_signing_configuration(signingConfiguration=good_config)
    got = ecr.get_signing_configuration()["signingConfiguration"]
    assert got == good_config, f"expected {good_config}, got {got}"


def _client_error(fn):
    """Call fn(); return the (code, message) of the ClientError it raises. An unexpected success
    raises, so an emulator that accepts what AWS refuses fails loudly instead of reading as a
    code mismatch."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _snapshot_signing_configuration(ecr):
    try:
        return ecr.get_signing_configuration()["signingConfiguration"]
    except ClientError as err:
        if err.response["Error"]["Code"] == "SigningConfigurationNotFoundException":
            return None
        raise


def _restore_signing_configuration(ecr, original):
    try:
        ecr.delete_signing_configuration()
    except ClientError as err:
        if err.response["Error"]["Code"] != "SigningConfigurationNotFoundException":
            raise
    if original is not None:
        ecr.put_signing_configuration(signingConfiguration=original)


def _valid_signing_configuration(account_id, region, profile_name):
    return {
        "rules": [
            {"signingProfileArn": f"arn:aws:signer:{region}:{account_id}:/signing-profiles/{profile_name}"}
        ]
    }


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
