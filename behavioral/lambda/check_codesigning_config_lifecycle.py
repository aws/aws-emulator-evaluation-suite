"""codesigning-config-lifecycle."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "codesigning-config-lifecycle"
GROUP = "state-machine"
SERVICES = ["lambda"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Full CRUD lifecycle of a code signing config ends in ResourceNotFoundException after delete."""
    lam = ctx.client("lambda")
    profile_arn = _signing_profile_version_arn(ctx)

    created = lam.create_code_signing_config(
        AllowedPublishers={"SigningProfileVersionArns": [profile_arn]},
        CodeSigningPolicies={"UntrustedArtifactOnDeployment": "Warn"},
        Description="sim2real behavioral check",
        Tags={"sim2real:managed": "true"},
    )["CodeSigningConfig"]
    arn = created["CodeSigningConfigArn"]
    ctx.on_cleanup(lambda: _delete_csc_ignore(lam, arn))
    assert created["AllowedPublishers"]["SigningProfileVersionArns"] == [profile_arn], (
        f"expected publishers [{profile_arn}], got {created['AllowedPublishers']['SigningProfileVersionArns']}"
    )
    assert created["CodeSigningPolicies"]["UntrustedArtifactOnDeployment"] == "Warn", (
        f"expected policy Warn, got {created['CodeSigningPolicies']['UntrustedArtifactOnDeployment']}"
    )

    got = lam.get_code_signing_config(CodeSigningConfigArn=arn)["CodeSigningConfig"]
    assert got["CodeSigningConfigArn"] == arn, f"expected arn {arn}, got {got['CodeSigningConfigArn']}"
    assert got["CodeSigningPolicies"]["UntrustedArtifactOnDeployment"] == "Warn", (
        f"expected policy Warn on independent read, got {got['CodeSigningPolicies']['UntrustedArtifactOnDeployment']}"
    )

    updated = lam.update_code_signing_config(
        CodeSigningConfigArn=arn,
        CodeSigningPolicies={"UntrustedArtifactOnDeployment": "Enforce"},
    )["CodeSigningConfig"]
    assert updated["CodeSigningPolicies"]["UntrustedArtifactOnDeployment"] == "Enforce", (
        f"expected policy Enforce, got {updated['CodeSigningPolicies']['UntrustedArtifactOnDeployment']}"
    )

    got_after_update = lam.get_code_signing_config(CodeSigningConfigArn=arn)["CodeSigningConfig"]
    assert got_after_update["CodeSigningPolicies"]["UntrustedArtifactOnDeployment"] == "Enforce", (
        f"expected policy Enforce on independent read, got {got_after_update['CodeSigningPolicies']['UntrustedArtifactOnDeployment']}"
    )

    lam.delete_code_signing_config(CodeSigningConfigArn=arn)

    code, message = _client_error(lambda: lam.get_code_signing_config(CodeSigningConfigArn=arn))
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException on get, got {code}"
    assert message == _csc_not_found_message(arn), (
        f"expected message {_csc_not_found_message(arn)!r} on get, got {message!r}"
    )

    update_code, update_message = _client_error(
        lambda: lam.update_code_signing_config(
            CodeSigningConfigArn=arn,
            CodeSigningPolicies={"UntrustedArtifactOnDeployment": "Warn"},
        )
    )
    assert update_code == "ResourceNotFoundException", (
        f"expected update on deleted config to raise ResourceNotFoundException, got {update_code}"
    )
    assert update_message == _csc_not_found_message(arn), (
        f"expected message {_csc_not_found_message(arn)!r} on update of the deleted config, got {update_message!r}"
    )


def _client_error(call):
    """Run a call that MUST be refused and return its (code, message). An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = call()
    except ClientError as e:
        err = e.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")


def _csc_not_found_message(csc_arn: str) -> str:
    return f"The Lambda code signing configuration {csc_arn} can not be found."


def _signing_profile_version_arn(ctx) -> str:
    """Create this check's own Signer profile (cancelled at cleanup) and return its version ARN."""
    import uuid

    signer = ctx.client("signer")
    name = "sim2realbehav" + uuid.uuid4().hex[:16]
    prof = signer.put_signing_profile(
        profileName=name,
        platformId="AWSLambda-SHA384-ECDSA",
        tags={"sim2real-check": CHECK},
    )
    ctx.on_cleanup(lambda: signer.cancel_signing_profile(profileName=name))
    return prof["profileVersionArn"]


def _delete_csc_ignore(lam, arn: str) -> None:
    from botocore.exceptions import ClientError

    try:
        lam.delete_code_signing_config(CodeSigningConfigArn=arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "CodeSigningConfigNotFoundException",
            "ResourceNotFoundException",
        ):
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
