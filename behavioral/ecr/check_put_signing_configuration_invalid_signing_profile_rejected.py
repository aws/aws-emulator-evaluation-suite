"""put-signing-configuration-invalid-signing-profile-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "put-signing-configuration-invalid-signing-profile-rejected"
GROUP = "overly-permissive"
SERVICES = ["ecr"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:ecr-signing-configuration")
def run(ctx) -> None:
    """PutSigningConfiguration with a signingProfileArn that is not an ARN is refused
    InvalidParameterException with the exact message and changes nothing, while a rule naming a
    real signing profile is stored."""
    ecr = ctx.client("ecr")
    signer = ctx.client("signer")

    original = _current_signing_config(ecr)
    ctx.on_cleanup(lambda: _restore_signing_config(ecr, original))

    # A real Signer signing profile, so the positive control references a genuine target.
    profile_name = ctx.unique_name("sim2realecrsig").replace("-", "")
    put_profile_resp = signer.put_signing_profile(
        profileName=profile_name,
        platformId="Notation-OCI-SHA384-ECDSA",
        tags={"sim2real": CHECK},
    )
    ctx.on_cleanup(lambda: signer.cancel_signing_profile(profileName=profile_name))
    real_profile_arn = put_profile_resp["arn"]

    fake_profile_arn = "not-a-valid-signer-profile-arn"

    bad_config = {"rules": [{"signingProfileArn": fake_profile_arn}]}
    code, message = _client_error(lambda: ecr.put_signing_configuration(signingConfiguration=bad_config))
    assert code == "InvalidParameterException", f"unexpected code: {code}"
    expected = (
        "Invalid parameter at 'signingProfileArn' failed to satisfy constraint: "
        f"'The signing profile ARN '{bad_config['rules'][0]['signingProfileArn']}' must be well formed'"
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Effect absent: signing configuration unchanged from the pre-mutation state.
    after_bad = _current_signing_config(ecr)
    assert after_bad == original, "signing configuration mutated despite rejection"

    # Positive control: same shape, but the nonexistent profile (the one blocking
    # condition) is replaced with the real profile ARN; this succeeds and persists.
    good_config = {"rules": [{"signingProfileArn": real_profile_arn}]}
    ecr.put_signing_configuration(signingConfiguration=good_config)
    persisted = _current_signing_config(ecr)
    assert persisted is not None, "signing configuration missing after accepted put"
    assert persisted["rules"][0]["signingProfileArn"] == real_profile_arn, (
        f"expected persisted profile arn {real_profile_arn!r}, got {persisted!r}"
    )


def _client_error(fn):
    """Call fn(); return the (code, message) of the ClientError it raises. An unexpected success
    raises, so an emulator that accepts what AWS refuses fails loudly instead of reading as a
    code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _current_signing_config(ecr):
    from botocore.exceptions import ClientError

    try:
        return ecr.get_signing_configuration()["signingConfiguration"]
    except ClientError as err:
        if err.response["Error"]["Code"] == "SigningConfigurationNotFoundException":
            return None
        raise


def _restore_signing_config(ecr, original):
    from botocore.exceptions import ClientError

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
