"""get-document-invalid-version-fails."""
from __future__ import annotations

import json
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-document-invalid-version-fails"
GROUP = 'overly-permissive'
SERVICES = ['ssm']

def _minimal_document_content():
    """A minimal, valid SSM Command document (JSON schema v2.2)."""
    return json.dumps(
        {
            "schemaVersion": "2.2",
            "description": "behavioral-fidelity-probe document",
            "parameters": {},
            "mainSteps": [
                {
                    "action": "aws:runShellScript",
                    "name": "runShellScript",
                    "inputs": {"runCommand": ["echo hello"]},
                }
            ],
        }
    )

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Overly-permissive check: GetDocument with a nonexistent DocumentVersion or VersionName
    fails with its exact code and message, on a document whose real version and version name
    are proven reachable first."""

    ssm = ctx.client("ssm")

    def _error_code(fn):
        """Call fn(); return its botocore (code, message). An unexpected success raises, because
        accepting a version AWS refuses must fail loudly rather than read as a code mismatch."""
        try:
            result = fn()
        except ClientError as exc:
            error = exc.response.get("Error", {})
            return error.get("Code"), error.get("Message")
        raise AssertionError(
            f"expected GetDocument to reject the version, but it SUCCEEDED: {result!r}"
        )

    def _track_document(name):
        ctx.on_cleanup(lambda: ssm.delete_document(Name=name, Force=True))
        return name

    name = ctx.unique_name("sim2real-behav-probe-doc-badversion-")
    _track_document(name)
    content = _minimal_document_content()
    ssm.create_document(
        Name=name,
        Content=content,
        DocumentType="Command",
        VersionName="release-one",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )

    # Positive control: version "1" is the real version CreateDocument just produced, so
    # GetDocument must serve it. Without this, a target where GetDocument fails for EVERY
    # version of this document (not just the invalid one) would pass the negative below.
    control = ssm.get_document(Name=name, DocumentVersion="1")
    assert control["Name"] == name, f"expected Name={name!r}, got {control.get('Name')!r}"
    assert control["DocumentVersion"] == "1", (
        f"expected DocumentVersion='1', got {control.get('DocumentVersion')!r}"
    )

    code, message = _error_code(lambda: ssm.get_document(Name=name, DocumentVersion="99"))
    assert code == "InvalidDocumentVersion", f"expected InvalidDocumentVersion, got {code!r}"
    assert message == "Document version: 99 is invalid, latest version is 1", (
        f"GetDocument DocumentVersion=99 message: {message!r}"
    )

    by_name = ssm.get_document(Name=name, VersionName="release-one")
    assert (by_name["Name"], by_name["DocumentVersion"], by_name["VersionName"]) == (
        name,
        "1",
        "release-one",
    ), f"GetDocument by VersionName returned {by_name!r}"

    code, message = _error_code(lambda: ssm.get_document(Name=name, VersionName="release-two"))
    assert (code, message) == (
        "InvalidDocument",
        f"Document with name {name} with version release-two does not exist.",
    ), f"GetDocument with a missing VersionName gave {code!r}: {message!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
