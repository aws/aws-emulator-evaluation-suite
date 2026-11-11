"""update-document-rejects-duplicate-content."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-document-rejects-duplicate-content"
GROUP = 'overly-permissive'
SERVICES = ['ssm']

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """UpdateDocument with new content creates version 2, while the same content again fails with
    DuplicateDocumentContent and the exact message and leaves two versions with LatestVersion 2."""

    ssm = ctx.client("ssm")

    def _run_shell_doc_content(command="echo hello"):
        return json.dumps(
            {
                "schemaVersion": "2.2",
                "description": "behavioral-fidelity-probe document",
                "mainSteps": [
                    {
                        "action": "aws:runShellScript",
                        "name": "runShellScript",
                        "inputs": {"runCommand": [command]},
                    }
                ],
            }
        )

    def _poll_until(probe, predicate, *, timeout_s=60, interval_s=1.0):
        deadline = time.monotonic() + timeout_s
        last = None
        while time.monotonic() < deadline:
            last = probe()
            if predicate(last):
                return last
            time.sleep(interval_s)
        raise AssertionError(f"condition not met within {timeout_s}s. Last: {last!r}")

    def _error_code(fn):
        try:
            result = fn()
        except ClientError as exc:
            err = exc.response.get("Error", {})
            return err.get("Code"), err.get("Message")
        raise AssertionError(f"expected a rejection, but the call SUCCEEDED: {result!r}")

    def _create_command_document(command="echo hello"):
        name = ctx.unique_name("sim2real-behav-probe-doc-")
        ctx.on_cleanup(lambda: ssm.delete_document(Name=name, Force=True))
        ssm.create_document(
            Content=_run_shell_doc_content(command),
            Name=name,
            DocumentType="Command",
            DocumentFormat="JSON",
            Tags=[{"Key": "sim2real-behavioral-probe", "Value": CHECK}],
        )
        _poll_until(
            lambda: ssm.describe_document(Name=name)["Document"]["Status"],
            lambda s: s in ("Active", "Failed"),
            timeout_s=60,
            interval_s=1,
        )
        return name

    name = _create_command_document("echo same")

    # Positive control: a genuinely different update must succeed and mint version 2 —
    # without this, "rejects duplicate content" is indistinguishable from "rejects every
    # UpdateDocument call".
    update_resp = ssm.update_document(
        Content=_run_shell_doc_content("echo different"),
        Name=name,
        DocumentVersion="$LATEST",
    )
    new_version = update_resp["DocumentDescription"]["DocumentVersion"]
    assert new_version == "2", f"expected version 2 after a genuinely different update, got {new_version!r}"

    code, message = _error_code(
        lambda: ssm.update_document(
            Content=_run_shell_doc_content("echo different"),
            Name=name,
            DocumentVersion="$LATEST",
        )
    )
    assert code == "DuplicateDocumentContent", f"expected DuplicateDocumentContent, got {code!r}"
    assert message == (
        f"Document to be updated with name {name} has the same metadata and content as document "
        "version provided in request"
    ), message

    versions = ssm.list_document_versions(Name=name)["DocumentVersions"]
    assert len(versions) == 2, f"a rejected UpdateDocument must not create a new version, got {len(versions)} versions"
    doc = ssm.describe_document(Name=name)["Document"]
    assert doc["LatestVersion"] == "2", f"expected LatestVersion to remain 2, got {doc['LatestVersion']!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
