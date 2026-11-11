"""document-get-and-list-filters."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "document-get-and-list-filters"
GROUP = 'state-machine'
SERVICES = ['ssm']

@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetDocument returns versioned content; ListDocuments honours the Name filter."""

    ssm = ctx.client("ssm")
    account_id = ctx.client("sts").get_caller_identity()["Account"]

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
        raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")

    def _create_command_document(command="echo hello"):
        name = ctx.unique_name("sim2real-behav-probe-doc-")
        ctx.on_cleanup(lambda: ssm.delete_document(Name=name, Force=True))
        ssm.create_document(
            Content=_run_shell_doc_content(command),
            Name=name,
            DocumentType="Command",
            DocumentFormat="JSON",
            Tags=[{"Key": "sim2real", "Value": CHECK}],
        )
        _poll_until(
            lambda: ssm.describe_document(Name=name)["Document"]["Status"],
            lambda s: s in ("Active", "Failed"),
            timeout_s=60,
            interval_s=1,
        )
        return name

    name = _create_command_document("echo findme")

    doc = ssm.get_document(Name=name, DocumentVersion="1")
    assert doc["Name"] == name, doc
    assert doc["Status"] == "Active", doc
    assert doc["DocumentType"] == "Command", doc
    assert doc["DocumentVersion"] == "1", doc
    assert "echo findme" in doc["Content"], doc["Content"]

    # ListDocuments is served from an index that lags CreateDocument, so poll.
    def find_self_owned():
        paginator = ssm.get_paginator("list_documents")
        for page in paginator.paginate(
            Filters=[{"Key": "Owner", "Values": ["Self"]}]
        ):
            for d in page["DocumentIdentifiers"]:
                if d["Name"] == name:
                    return d
        return None

    entry = _poll_until(
        find_self_owned, lambda d: d is not None, timeout_s=120, interval_s=5
    )
    assert entry["DocumentType"] == "Command", entry
    assert entry["Owner"] == account_id, entry

    # The DocumentType filter must exclude a Command document.
    automation_only = []
    paginator = ssm.get_paginator("list_documents")
    for page in paginator.paginate(
        Filters=[
            {"Key": "Owner", "Values": ["Self"]},
            {"Key": "DocumentType", "Values": ["Automation"]},
        ]
    ):
        automation_only.extend(page["DocumentIdentifiers"])
    assert all(d["Name"] != name for d in automation_only), (
        "a Command document must not match a DocumentType=Automation filter"
    )

    code, message = _error_code(lambda: ssm.get_document(Name=name, DocumentVersion="7"))
    assert code == "InvalidDocumentVersion", f"expected InvalidDocumentVersion, got {code!r}"
    assert message == "Document version: 7 is invalid, latest version is 1", message


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
