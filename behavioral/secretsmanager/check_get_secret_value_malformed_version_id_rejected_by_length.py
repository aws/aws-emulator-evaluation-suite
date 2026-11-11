"""get-secret-value-malformed-version-id-rejected-by-length."""
from __future__ import annotations

from botocore.client import Config
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-secret-value-malformed-version-id-rejected-by-length"
GROUP = "validation"
SERVICES = ["secretsmanager"]


@tags(
    "axis:rejection",
    "cap:c1",
    "concern:negative-classes",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """GetSecretValue refuses a VersionId shorter than the modelled 32-character floor with
    ValidationException, distinct from a well-formed-but-nonexistent VersionId's
    ResourceNotFoundException; the real version is left untouched.
    """
    # botocore enforces the 32-character floor client-side; disable it so the service judges it.
    sm = ctx.client("secretsmanager", config=Config(parameter_validation=False))
    name = ctx.unique_name("sim2real-behav-smshortver-")
    created = sm.create_secret(
        Name=name,
        SecretString="current-value",
        Tags=[
            {"Key": "sim2real", "Value": CHECK},
            {"Key": "sim2real:managed", "Value": "true"},
        ],
    )
    arn = created["ARN"]
    ctx.on_cleanup(lambda: sm.delete_secret(SecretId=arn, ForceDeleteWithoutRecovery=True))

    # Positive control: the real current version reads back fine, without a VersionId at all.
    control = sm.get_secret_value(SecretId=arn)
    assert control["SecretString"] == "current-value", (
        f"expected 'current-value', got {control.get('SecretString')!r}"
    )

    short_id = "too-short-for-a-version-id"
    assert len(short_id) < 32, "the probed VersionId must sit below the modelled 32-char floor"

    code, message = _error_code(lambda: sm.get_secret_value(SecretId=arn, VersionId=short_id))
    assert code == "ValidationException", (
        f"a VersionId shorter than 32 characters must be refused with ValidationException, got "
        f"{code!r}"
    )
    assert message == (
        f"1 validation error detected: Value '{short_id}' at 'versionId' failed to satisfy "
        "constraint: Member must have length greater than or equal to 32"
    ), f"unexpected message for a too-short VersionId: {message!r}"

    # Effect absent: the refused call did not move or corrupt the real version.
    after = sm.get_secret_value(SecretId=arn)
    assert after["VersionId"] == control["VersionId"], (
        f"expected version to remain {control['VersionId']}, got {after.get('VersionId')!r}"
    )
    assert after["SecretString"] == "current-value", (
        f"expected 'current-value' after the refused call, got {after.get('SecretString')!r}"
    )


def _error_code(fn):
    """Call fn(); return the botocore (Error.Code, Error.Message) if a ClientError was raised. An
    unexpected success raises, so accepting what AWS refuses is named, not read as a mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
