"""get-aws-owned-run-shell-script-document-shape."""

from __future__ import annotations

import json
import re

from behavioral_harness import tags

CHECK = "get-aws-owned-run-shell-script-document-shape"
GROUP = "representation"
SERVICES = ["ssm"]

_NAME = "AWS-RunShellScript"


@tags("axis:happy-path", "cap:c5", "concern:representation", "plane:control")
def run(ctx) -> None:
    """The AWS-owned AWS-RunShellScript document reads as an Active Amazon-owned Command document.

    Its JSON content declares a commands parameter and an aws:runShellScript plugin.
    """
    ssm = ctx.client("ssm")

    got = ssm.get_document(Name=_NAME)
    assert (got["Name"], got["DocumentType"], got["DocumentFormat"], got["Status"]) == (
        _NAME,
        "Command",
        "JSON",
        "Active",
    ), f"GetDocument {_NAME} returned {got!r}"
    assert re.fullmatch(r"[1-9][0-9]*", got["DocumentVersion"]), (
        f"DocumentVersion {got['DocumentVersion']!r} is not a positive integer string"
    )

    content = json.loads(got["Content"])
    assert re.fullmatch(r"[0-9]+\.[0-9]+", content["schemaVersion"]), (
        f"schemaVersion {content['schemaVersion']!r} is not a major.minor string"
    )
    assert "commands" in content["parameters"], (
        f"content parameters are {sorted(content['parameters'])!r}, expected to include commands"
    )
    plugins = content["runtimeConfig"]
    assert "aws:runShellScript" in plugins, (
        f"content plugins are {sorted(plugins)!r}, expected to include aws:runShellScript"
    )

    described = ssm.describe_document(Name=_NAME)["Document"]
    assert (described["Name"], described["Owner"], described["DocumentType"]) == (
        _NAME,
        "Amazon",
        "Command",
    ), f"DescribeDocument {_NAME} returned {described!r}"
    assert "Linux" in described["PlatformTypes"], (
        f"PlatformTypes {described['PlatformTypes']!r} do not include Linux"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
