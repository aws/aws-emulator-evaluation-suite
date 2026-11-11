"""create-service-principal-name-arn-type-mismatch-rejected."""
from __future__ import annotations

import uuid

from behavioral_harness import tags

CHECK = "create-service-principal-name-arn-type-mismatch-rejected"
GROUP = "validation"
SERVICES = ["pca-connector-ad"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateServicePrincipalName rejects a DirectoryRegistrationArn that is a ConnectorArn with
    ValidationException and its exact message, while a correctly shaped DirectoryRegistrationArn gets
    ResourceNotFoundException with its exact message."""
    pcad = ctx.client("pca-connector-ad")
    account = ctx.client("sts").get_caller_identity()["Account"]
    connector_arn = f"arn:aws:pca-connector-ad:{ctx.region}:{account}:connector/{uuid.uuid4()}"
    directory_registration_arn = (
        f"arn:aws:pca-connector-ad:{ctx.region}:{account}:directory-registration/d-1234567890"
    )

    code, message = _error_code(
        lambda: pcad.create_service_principal_name(
            DirectoryRegistrationArn=connector_arn,  # wrong resource type on purpose
            ConnectorArn=connector_arn,
        )
    )
    assert code == "ValidationException", (
        f"expected ValidationException for a DirectoryRegistrationArn that is structurally a "
        f"ConnectorArn, got {code!r}"
    )
    assert message == (
        f"1 validation error detected: Value '{connector_arn}' at 'directoryRegistrationArn' "
        "failed to satisfy constraint: Member must satisfy regular expression pattern: "
        "arn:[\\w-]+:pca-connector-ad:[\\w-]+:[0-9]+:directory-registration\\/d-[0-9a-f]{10}"
    ), message

    control_code, control_message = _error_code(
        lambda: pcad.create_service_principal_name(
            DirectoryRegistrationArn=directory_registration_arn,
            ConnectorArn=connector_arn,
        )
    )
    assert control_code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException once the ARN shape is a well-formed "
        f"directory-registration ARN pointing at a nonexistent resource, got {control_code!r} "
        f"-- if this is ValidationException too, the first rejection above was about the ARN "
        f"shape, not resource-type confusion"
    )
    assert control_message == (
        f"DirectoryRegistration was not found: {directory_registration_arn}."
    ), control_message


def _error_code(fn):
    """Call fn(); return its botocore Error (code, message). An unexpected SUCCESS raises, because
    an emulator ACCEPTING input real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except Exception as exc:  # noqa: BLE001
        resp = getattr(exc, "response", None)
        if resp:
            err = resp.get("Error", {})
            return err.get("Code"), err.get("Message")
        return type(exc).__name__, str(exc)
    raise AssertionError(
        f"expected create_service_principal_name to be rejected, but it SUCCEEDED and returned "
        f"{result!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
