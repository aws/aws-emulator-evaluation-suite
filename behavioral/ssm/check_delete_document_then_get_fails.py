"""delete-document-then-get-fails."""
from __future__ import annotations

import json
import time
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-document-then-get-fails"
GROUP = 'state-machine'
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

def _poll_until(probe, predicate, *, timeout_s=30, interval_s=1.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """State machine: GetDocument resolves the name while it exists (positive control); after
    DeleteDocument, GetDocument and UpdateDocument refuse it with InvalidDocument and its exact
    message; and the freed name is reusable by a fresh CreateDocument."""

    ssm = ctx.client("ssm")

    def _error_code(fn):
        try:
            result = fn()
        except ClientError as exc:
            error = exc.response.get("Error", {})
            return error.get("Code"), error.get("Message")
        raise AssertionError(f"expected the call to be rejected, but it succeeded with {result!r}")

    name = ctx.unique_name("sim2real-behav-probe-doc-delete-")
    content = _minimal_document_content()

    def _delete_if_present():
        try:
            ssm.delete_document(Name=name, Force=True)
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "InvalidDocument":
                raise

    ctx.on_cleanup(_delete_if_present)
    ssm.create_document(
        Name=name,
        Content=content,
        DocumentType="Command",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )

    def status():
        return ssm.describe_document(Name=name)["Document"]["Status"]

    final_status = _poll_until(
        status, lambda s: s in ("Active", "Failed"), description="probe document to leave Creating"
    )
    assert final_status == "Active", f"expected the probe document to become Active, got {final_status!r}"

    # Positive control: the name resolves while the document exists, so a later InvalidDocument
    # is evidence the delete took effect -- not evidence that GetDocument rejects any name.
    before = ssm.get_document(Name=name)
    assert before["Name"] == name, f"expected GetDocument to resolve {name!r} before delete, got {before!r}"

    ssm.delete_document(Name=name)

    code, message = _error_code(lambda: ssm.get_document(Name=name))
    assert code == "InvalidDocument", f"expected InvalidDocument after delete, got {code!r}"
    assert message == f"Document with name {name} does not exist.", (
        f"GetDocument on a deleted document message: {message!r}"
    )

    # The dead name also rejects a mutation, not just a read. Unlike GetDocument's
    # InvalidDocument, UpdateDocument's carries no message text.
    update_code, update_message = _error_code(
        lambda: ssm.update_document(Name=name, Content=content, DocumentVersion="$LATEST")
    )
    assert update_code == "InvalidDocument", (
        f"expected UpdateDocument on a deleted document to fail with InvalidDocument, got {update_code!r}"
    )
    assert update_message == "", (
        f"expected UpdateDocument's InvalidDocument on a deleted document to carry no message, "
        f"got {update_message!r}"
    )

    # The freed name is reusable.
    ssm.create_document(
        Name=name,
        Content=content,
        DocumentType="Command",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    recreated = ssm.get_document(Name=name)
    assert recreated["Name"] == name, f"expected the freed name {name!r} to be reusable, got {recreated!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
