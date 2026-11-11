"""document-tags-roundtrip."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "document-tags-roundtrip"
GROUP = 'state-machine'
SERVICES = ['ssm']

@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """AddTagsToResource/ListTagsForResource round-trip for a Document resource."""

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

    def _create_command_document(command="echo hello"):
        name = ctx.unique_name("sim2real-behav-probe-doc-")
        ctx.on_cleanup(lambda: ssm.delete_document(Name=name, Force=True))
        ssm.create_document(
            Content=_run_shell_doc_content(command),
            Name=name,
            DocumentType="Command",
            DocumentFormat="JSON",
        )
        _poll_until(
            lambda: ssm.describe_document(Name=name)["Document"]["Status"],
            lambda s: s in ("Active", "Failed"),
            timeout_s=60,
            interval_s=1,
        )
        return name

    name = _create_command_document()

    ssm.add_tags_to_resource(
        ResourceType="Document",
        ResourceId=name,
        Tags=[{"Key": "team", "Value": "probe"}],
    )
    tags = ssm.list_tags_for_resource(ResourceType="Document", ResourceId=name)["TagList"]
    assert {"Key": "team", "Value": "probe"} in tags, f"expected tag team=probe in {tags}"

    ssm.remove_tags_from_resource(
        ResourceType="Document", ResourceId=name, TagKeys=["team"]
    )
    tags_after = ssm.list_tags_for_resource(
        ResourceType="Document", ResourceId=name
    )["TagList"]
    assert tags_after == [], f"expected no tags after removal, got {tags_after}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
