"""update-document-default-version-nonexistent-version-rejected."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-document-default-version-nonexistent-version-rejected"
GROUP = "error-semantics"
SERVICES = ["ssm"]


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
    """UpdateDocumentDefaultVersion rejects a DocumentVersion the document never reached, and
    still accepts the version this check actually created."""
    ssm = ctx.client("ssm")

    doc_name = ctx.unique_name("sim2real-ssm-doc-")
    ssm.create_document(
        Name=doc_name,
        DocumentType="Command",
        DocumentFormat="JSON",
        Content=json.dumps(
            {
                "schemaVersion": "2.2",
                "description": "a document with exactly one version",
                "mainSteps": [
                    {"action": "aws:runShellScript", "name": "echoStep", "inputs": {"runCommand": ["echo sim2real"]}}
                ],
            }
        ),
    )
    ctx.on_cleanup(lambda: ssm.delete_document(Name=doc_name, Force=True))

    missing_version = "7"
    expected = (
        "InvalidDocumentVersion",
        f"Document with name {doc_name} with version {missing_version} does not exist.",
    )
    got = _error(
        lambda: ssm.update_document_default_version(Name=doc_name, DocumentVersion=missing_version)
    )
    assert got == expected, f"expected {expected!r}, got {got!r}"

    updated = ssm.update_document_default_version(Name=doc_name, DocumentVersion="1")["Description"]
    assert updated["DefaultVersion"] == "1", updated


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
