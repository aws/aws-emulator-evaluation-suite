"""modify-document-permission-validation-rejected."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "modify-document-permission-validation-rejected"
GROUP = "error-semantics"
SERVICES = ["ssm"]

_NEITHER_ADD_NOR_REMOVE = (
    "InvalidParameterException",
    "Either AccountIdsToAdd or AccountIdsToRemove must be specified for API operation",
)
_MALFORMED_ACCOUNT_ID = (
    "ValidationException",
    "1 validation error detected: Value '[123]' at 'accountIdsToAdd' failed to satisfy "
    "constraint: Member must satisfy constraint: [Member must have length less than or equal "
    "to 12, Member must have length greater than or equal to 0, Member must satisfy regular "
    "expression pattern: (?i)all|[0-9]{12}]",
)


def _error(fn) -> tuple:
    """(Error.Code, Error.Message) raised by ``fn``; an unexpected success raises too."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err["Message"]
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ModifyDocumentPermission rejects a call naming neither account list, an account id that
    is not 12 digits or "all", and shares a document with a 12-digit account id."""
    ssm = ctx.client("ssm")

    doc_name = ctx.unique_name("sim2real-ssm-doc-")
    ssm.create_document(
        Name=doc_name,
        DocumentType="Command",
        DocumentFormat="JSON",
        Content=json.dumps(
            {
                "schemaVersion": "2.2",
                "description": "a document whose sharing permissions this check modifies",
                "mainSteps": [
                    {"action": "aws:runShellScript", "name": "echoStep", "inputs": {"runCommand": ["echo sim2real"]}}
                ],
            }
        ),
    )
    ctx.on_cleanup(lambda: ssm.delete_document(Name=doc_name, Force=True))

    got = _error(lambda: ssm.modify_document_permission(Name=doc_name, PermissionType="Share"))
    assert got == _NEITHER_ADD_NOR_REMOVE, f"expected {_NEITHER_ADD_NOR_REMOVE!r}, got {got!r}"

    got = _error(
        lambda: ssm.modify_document_permission(
            Name=doc_name, PermissionType="Share", AccountIdsToAdd=["123"]
        )
    )
    assert got == _MALFORMED_ACCOUNT_ID, f"expected {_MALFORMED_ACCOUNT_ID!r}, got {got!r}"

    ssm.modify_document_permission(
        Name=doc_name, PermissionType="Share", AccountIdsToAdd=[ctx.account]
    )
    ctx.on_cleanup(
        lambda: ssm.modify_document_permission(
            Name=doc_name, PermissionType="Share", AccountIdsToRemove=[ctx.account]
        )
    )
    shared_with = ssm.describe_document_permission(Name=doc_name, PermissionType="Share")["AccountIds"]
    assert shared_with == [ctx.account], shared_with


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
