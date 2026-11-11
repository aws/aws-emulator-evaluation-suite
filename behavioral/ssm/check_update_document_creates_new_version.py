"""update-document-creates-new-version."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "update-document-creates-new-version"
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
    """UpdateDocument creates a new DocumentVersion without changing the default version."""

    ssm = ctx.client("ssm")

    def _track_document(name):
        ctx.on_cleanup(lambda: ssm.delete_document(Name=name, Force=True))
        return name

    import json

    name = ctx.unique_name("sim2real-behav-probe-doc-update-")
    _track_document(name)
    content = _minimal_document_content()
    create_resp = ssm.create_document(Name=name, Content=content, DocumentType="Command")
    original_default = create_resp["DocumentDescription"]["DocumentVersion"]

    new_content = json.loads(content)
    new_content["description"] = "updated content"
    update_resp = ssm.update_document(
        Name=name, Content=json.dumps(new_content), DocumentVersion="$LATEST"
    )
    new_version = update_resp["DocumentDescription"]["DocumentVersion"]

    assert new_version != original_default, "update must create a distinct new version"

    desc = ssm.describe_document(Name=name)["Document"]
    assert desc["DocumentVersion"] == original_default, (
        "default version must not change until UpdateDocumentDefaultVersion is called"
    )

    default_content = json.loads(ssm.get_document(Name=name)["Content"])
    assert default_content["description"] == "behavioral-fidelity-probe document", (
        f"unpinned GetDocument must still resolve the original default content, "
        f"got description={default_content.get('description')!r}"
    )

    new_version_content = json.loads(
        ssm.get_document(Name=name, DocumentVersion=new_version)["Content"]
    )
    assert new_version_content["description"] == "updated content", (
        f"the new DocumentVersion must resolve the updated content, "
        f"got description={new_version_content.get('description')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
