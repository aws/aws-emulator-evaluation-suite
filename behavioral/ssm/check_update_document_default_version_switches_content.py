"""update-document-default-version-switches-content."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "update-document-default-version-switches-content"
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
    """An unpinned GetDocument returns the default version: still the old content after
    UpdateDocument, and the new content only after UpdateDocumentDefaultVersion."""

    ssm = ctx.client("ssm")

    def _track_document(name):
        ctx.on_cleanup(lambda: ssm.delete_document(Name=name, Force=True))
        return name

    name = ctx.unique_name("sim2real-behav-probe-doc-default-")
    _track_document(name)
    content = _minimal_document_content()
    ssm.create_document(Name=name, Content=content, DocumentType="Command")

    before = ssm.get_document(Name=name)
    assert json.loads(before["Content"])["description"] == "behavioral-fidelity-probe document", (
        f"expected the original content before any update, got {before['Content']!r}"
    )

    new_content = json.loads(content)
    new_content["description"] = "second revision"
    update_resp = ssm.update_document(
        Name=name, Content=json.dumps(new_content), DocumentVersion="$LATEST"
    )
    new_version = update_resp["DocumentDescription"]["DocumentVersion"]

    mid = ssm.get_document(Name=name)
    assert json.loads(mid["Content"])["description"] == "behavioral-fidelity-probe document", (
        "an unpinned GetDocument must still resolve the DEFAULT version, not the newly "
        f"created one, until UpdateDocumentDefaultVersion is called; got {mid['Content']!r}"
    )

    ssm.update_document_default_version(Name=name, DocumentVersion=new_version)

    got = ssm.get_document(Name=name)
    assert json.loads(got["Content"])["description"] == "second revision", (
        f"expected the new default version's content after the switch, got {got['Content']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
