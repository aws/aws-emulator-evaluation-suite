"""create-document-duplicate-name-fails."""
from __future__ import annotations

import json
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-document-duplicate-name-fails"
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
    """Overly-permissive check: CreateDocument with an already-used Name must fail,
    leave the original document untouched, and the name must become usable again
    once that original is deleted."""

    ssm = ctx.client("ssm")

    def _expect_error(op_desc, fn):
        try:
            result = fn()
        except ClientError as exc:
            err = exc.response.get("Error", {})
            return err.get("Code"), err.get("Message")
        raise AssertionError(f"expected {op_desc} to fail, but it SUCCEEDED and returned {result!r}")

    name = ctx.unique_name("sim2real-behav-probe-doc-dup-")
    ctx.on_cleanup(lambda: ssm.delete_document(Name=name, Force=True))
    content = _minimal_document_content()

    # Positive control: the name is free, so CreateDocument succeeds.
    original = ssm.create_document(Name=name, Content=content, DocumentType="Command")[
        "DocumentDescription"
    ]
    assert original["Name"] == name, original
    assert original["DocumentVersion"] == "1", original

    # Break: the identical call with an already-taken Name is rejected with the
    # specific conflict code.
    code, message = _expect_error(
        "CreateDocument with an already-used Name",
        lambda: ssm.create_document(Name=name, Content=content, DocumentType="Command"),
    )
    assert code == "DocumentAlreadyExists", f"expected DocumentAlreadyExists, got {code!r}"
    assert message == f"Document with same name {name} already exists", message

    # Effect absent: an independent read (DescribeDocument, not CreateDocument) shows
    # the rejected duplicate had zero effect -- same version and content hash as the
    # original.
    described = ssm.describe_document(Name=name)["Document"]
    assert described["DocumentVersion"] == "1", described
    assert described["Hash"] == original["Hash"], described

    # Restore: delete the original -- an independent read confirms it is really gone --
    # and the identical CreateDocument call now succeeds against the freed Name.
    ssm.delete_document(Name=name, Force=True)
    gone_code, gone_message = _expect_error("GetDocument after delete", lambda: ssm.get_document(Name=name))
    assert gone_code == "InvalidDocument", f"expected InvalidDocument after delete, got {gone_code!r}"
    assert gone_message == f"Document with name {name} does not exist.", gone_message

    ssm.create_document(Name=name, Content=content, DocumentType="Command")

    # Terminal read: an independent DescribeDocument (not the CreateDocument response
    # itself) confirms the freed Name is usable again as a fresh document, version "1".
    final = ssm.describe_document(Name=name)["Document"]
    assert final["Name"] == name, final
    assert final["DocumentVersion"] == "1", final


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
