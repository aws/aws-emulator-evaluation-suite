"""code-signing-config-lifecycle."""

from __future__ import annotations

import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "code-signing-config-lifecycle"
GROUP = 'code_signing'
SERVICES = ['lambda']


def _reject(fn):
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises, because an emulator
    ACCEPTING input real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"expected the call to be rejected, but it succeeded with {result!r}")


def _not_found_message(csc_arn):
    return f"The Lambda code signing configuration {csc_arn} can not be found."


def _delete_csc_ignore_not_found(lam, csc_arn):
    try:
        lam.delete_code_signing_config(CodeSigningConfigArn=csc_arn)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise


def _create_signing_profile(ctx):
    signer = ctx.client("signer")
    name = "sim2realbehav" + uuid.uuid4().hex[:16]
    signer.put_signing_profile(
        profileName=name,
        platformId="AWSLambda-SHA384-ECDSA",
        tags={"sim2real-check": CHECK},
    )
    ctx.on_cleanup(lambda: signer.cancel_signing_profile(profileName=name))
    prof = signer.get_signing_profile(profileName=name)
    return name, prof["profileVersionArn"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CodeSigningConfig create/update/delete lifecycle and listing consistency."""
    lam = ctx.client("lambda")
    _, sig_arn = _create_signing_profile(ctx)

    csc = lam.create_code_signing_config(
        Description="sim2real-behav csc",
        AllowedPublishers={"SigningProfileVersionArns": [sig_arn]},
        CodeSigningPolicies={"UntrustedArtifactOnDeployment": "Warn"},
        Tags={"sim2real-check": CHECK},
    )
    csc_arn = csc["CodeSigningConfig"]["CodeSigningConfigArn"]
    ctx.on_cleanup(lambda: _delete_csc_ignore_not_found(lam, csc_arn))
    assert csc["CodeSigningConfig"]["AllowedPublishers"]["SigningProfileVersionArns"] == [sig_arn], (
        f"create echoed AllowedPublishers {csc['CodeSigningConfig']['AllowedPublishers']!r}, "
        f"expected [{sig_arn!r}]"
    )

    got = lam.get_code_signing_config(CodeSigningConfigArn=csc_arn)
    assert got["CodeSigningConfig"]["CodeSigningPolicies"]["UntrustedArtifactOnDeployment"] == "Warn", (
        f"independent read after create showed policy "
        f"{got['CodeSigningConfig']['CodeSigningPolicies']!r}, expected 'Warn'"
    )

    updated = lam.update_code_signing_config(
        CodeSigningConfigArn=csc_arn,
        CodeSigningPolicies={"UntrustedArtifactOnDeployment": "Enforce"},
    )
    assert updated["CodeSigningConfig"]["CodeSigningPolicies"]["UntrustedArtifactOnDeployment"] == "Enforce", (
        f"update's own response showed policy "
        f"{updated['CodeSigningConfig']['CodeSigningPolicies']!r}, expected 'Enforce'"
    )
    got_after_update = lam.get_code_signing_config(CodeSigningConfigArn=csc_arn)
    assert got_after_update["CodeSigningConfig"]["CodeSigningPolicies"]["UntrustedArtifactOnDeployment"] == "Enforce", (
        f"independent read after update showed policy "
        f"{got_after_update['CodeSigningConfig']['CodeSigningPolicies']!r}, expected 'Enforce' -- "
        f"the update call's own echoed response is not proof it persisted"
    )

    listed = lam.list_code_signing_configs()["CodeSigningConfigs"]
    assert any(c["CodeSigningConfigArn"] == csc_arn for c in listed), (
        f"csc {csc_arn!r} not present in ListCodeSigningConfigs"
    )

    lam.delete_code_signing_config(CodeSigningConfigArn=csc_arn)

    error = _reject(lambda: lam.get_code_signing_config(CodeSigningConfigArn=csc_arn))
    assert error.get("Code") == "ResourceNotFoundException", (
        f"expected CSC gone, got {error.get('Code')!r}"
    )
    assert error.get("Message") == _not_found_message(csc_arn), (
        f"GetCodeSigningConfig on the deleted csc returned message {error.get('Message')!r}, "
        f"expected {_not_found_message(csc_arn)!r}"
    )

    listed2 = lam.list_code_signing_configs()["CodeSigningConfigs"]
    assert not any(c["CodeSigningConfigArn"] == csc_arn for c in listed2), (
        f"deleted csc {csc_arn!r} still present in ListCodeSigningConfigs"
    )

    mutate_error = _reject(lambda: lam.update_code_signing_config(
        CodeSigningConfigArn=csc_arn,
        CodeSigningPolicies={"UntrustedArtifactOnDeployment": "Warn"},
    ))
    assert mutate_error.get("Code") == "ResourceNotFoundException", (
        f"expected UpdateCodeSigningConfig on a deleted csc to fail with "
        f"ResourceNotFoundException, got {mutate_error.get('Code')!r}"
    )
    assert mutate_error.get("Message") == _not_found_message(csc_arn), (
        f"UpdateCodeSigningConfig on the deleted csc returned message "
        f"{mutate_error.get('Message')!r}, expected {_not_found_message(csc_arn)!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
