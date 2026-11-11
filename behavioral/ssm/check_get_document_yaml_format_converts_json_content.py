"""get-document-yaml-format-converts-json-content."""

from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "get-document-yaml-format-converts-json-content"
GROUP = "state-machine"
SERVICES = ["ssm"]

_CONTENT = json.dumps(
    {
        "schemaVersion": "2.2",
        "description": "yaml conversion document",
        "mainSteps": [
            {
                "action": "aws:runShellScript",
                "name": "run",
                "inputs": {"runCommand": ["echo hello"]},
            }
        ],
    }
)

_EXPECTED_YAML = (
    "---\n"
    'schemaVersion: "2.2"\n'
    'description: "yaml conversion document"\n'
    "mainSteps:\n"
    '- action: "aws:runShellScript"\n'
    '  name: "run"\n'
    "  inputs:\n"
    "    runCommand:\n"
    '    - "echo hello"\n'
)


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetDocument with DocumentFormat=YAML converts a JSON-authored document to exact YAML text.

    The default read still returns the JSON content byte for byte.
    """
    ssm = ctx.client("ssm")
    name = ctx.unique_name("sim2real-behav-yamldoc-")
    ssm.create_document(
        Name=name,
        Content=_CONTENT,
        DocumentType="Command",
        DocumentFormat="JSON",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: ssm.delete_document(Name=name, Force=True))

    deadline = time.monotonic() + min(60.0, ctx.time_left())
    while True:
        status = ssm.describe_document(Name=name)["Document"]["Status"]
        if status != "Creating" or time.monotonic() >= deadline:
            break
        time.sleep(2)
    assert status == "Active", f"document status is {status!r}, expected 'Active'"

    as_json = ssm.get_document(Name=name)
    assert (as_json["DocumentFormat"], as_json["Content"]) == ("JSON", _CONTENT), (
        f"default GetDocument returned {as_json['DocumentFormat']!r}: {as_json['Content']!r}"
    )

    as_yaml = ssm.get_document(Name=name, DocumentFormat="YAML")
    assert as_yaml["DocumentFormat"] == "YAML", (
        f"GetDocument DocumentFormat=YAML answered format {as_yaml['DocumentFormat']!r}"
    )
    assert as_yaml["Content"] == _EXPECTED_YAML, f"YAML content is {as_yaml['Content']!r}"
    assert as_yaml["DocumentVersion"] == "1", (
        f"YAML read DocumentVersion is {as_yaml['DocumentVersion']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
