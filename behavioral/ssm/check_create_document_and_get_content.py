"""create-document-and-get-content."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "create-document-and-get-content"
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

@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateDocument stores content retrievable verbatim via GetDocument, Status becomes Active."""

    ssm = ctx.client("ssm")

    def _poll_until(probe, predicate, *, timeout_s=60, interval_s=1.0, description="condition"):
        deadline = time.monotonic() + timeout_s
        last = None
        while time.monotonic() < deadline:
            last = probe()
            if predicate(last):
                return last
            time.sleep(interval_s)
        raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")

    def _track_document(name):
        ctx.on_cleanup(lambda: ssm.delete_document(Name=name, Force=True))
        return name

    name = ctx.unique_name("sim2real-behav-probe-doc-")
    _track_document(name)
    content = _minimal_document_content()

    create_resp = ssm.create_document(
        Name=name,
        Content=content,
        DocumentType="Command",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    assert create_resp["DocumentDescription"]["Name"] == name, (
        f"expected create response Name to echo {name!r}, got "
        f"{create_resp['DocumentDescription'].get('Name')!r}"
    )

    def probe():
        return ssm.describe_document(Name=name)["Document"]["Status"]

    status = _poll_until(probe, lambda s: s in ("Active", "Failed"), timeout_s=30, interval_s=1)
    assert status == "Active", f"expected document to become Active, got {status}"

    got = ssm.get_document(Name=name)
    assert got["DocumentType"] == "Command", (
        f"expected DocumentType 'Command', got {got.get('DocumentType')!r}"
    )
    got_content = json.loads(got["Content"])
    assert got_content == json.loads(content), (
        f"expected GetDocument content to round-trip verbatim, "
        f"expected {json.loads(content)!r} got {got_content!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
