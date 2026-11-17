"""list-document-versions-nonexistent-name-rejected."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-document-versions-nonexistent-name-rejected"
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
    """ListDocumentVersions rejects a Name no document ever used, and lists the sole version of
    a document this check creates."""
    ssm = ctx.client("ssm")

    missing_name = ctx.unique_name("sim2real-ssm-doc-never-created-")
    expected = (
        "InvalidDocument",
        f"Document with name {missing_name} does not exist.",
    )
    got = _error(lambda: ssm.list_document_versions(Name=missing_name))
    assert got == expected, f"expected {expected!r}, got {got!r}"

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

    versions = ssm.list_document_versions(Name=doc_name)["DocumentVersions"]
    assert [v["DocumentVersion"] for v in versions] == ["1"], versions


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
