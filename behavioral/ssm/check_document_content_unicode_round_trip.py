"""document-content-unicode-round-trip."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "document-content-unicode-round-trip"
GROUP = "representation"
SERVICES = ["ssm"]

_UNICODE_TEXT = "héllo wörld – 日本語のコメント – emoji test 🚀🔥 – naïve café"


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A document created with unicode/multi-byte content in its JSON body is returned
    byte-identical (no mangling, no escaping loss) via GetDocument."""
    ssm = ctx.client("ssm")
    name = ctx.unique_name("sim2real-unicode-doc-")
    content = {
        "schemaVersion": "2.2",
        "description": _UNICODE_TEXT,
        "mainSteps": [
            {
                "action": "aws:runShellScript",
                "name": "runShell",
                "inputs": {"runCommand": [f"echo '{_UNICODE_TEXT}'"]},
            }
        ],
    }

    ssm.create_document(
        Content=json.dumps(content, ensure_ascii=False),
        Name=name,
        DocumentType="Command",
        DocumentFormat="JSON",
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: ssm.delete_document(Name=name))

    got = ssm.get_document(Name=name, DocumentFormat="JSON")
    fetched = json.loads(got["Content"])
    assert fetched["description"] == _UNICODE_TEXT, (
        f"expected description {_UNICODE_TEXT!r}, got {fetched['description']!r}"
    )
    expected_run_command = [f"echo '{_UNICODE_TEXT}'"]
    actual_run_command = fetched["mainSteps"][0]["inputs"]["runCommand"]
    assert actual_run_command == expected_run_command, (
        f"expected runCommand {expected_run_command!r}, got {actual_run_command!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
