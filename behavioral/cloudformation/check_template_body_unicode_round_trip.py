"""template-body-unicode-round-trip."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "template-body-unicode-round-trip"
GROUP = "representation"
SERVICES = ["cloudformation"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetTemplate returns template Description/Metadata with every non-ASCII code point as '?'.

    CloudFormation coerces stored strings to ASCII (CJK, accents, Cyrillic, emoji alike), so a
    verbatim unicode round trip is a mismatch.
    """
    cfn = ctx.client("cloudformation")
    stack_name = ctx.unique_name("sim2real-behav-unicode-")

    description = "部署テンプレート 🚀 — café naïve, Zürich, Москва"
    metadata = {
        "sim2real": {
            "note": "emoji check 😀🔥 中文注释 π≈3.14159",
            "arrow": "→ ← ↔",
        }
    }
    template = {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Description": description,
        "Metadata": metadata,
        "Resources": {
            "Handle": {"Type": "AWS::CloudFormation::WaitConditionHandle"}
        },
    }
    template_body = json.dumps(template, ensure_ascii=False)

    cfn.create_stack(
        StackName=stack_name,
        TemplateBody=template_body,
        Tags=[{"Key": "sim2real-behav", "Value": "template-body-unicode-round-trip"}],
    )
    ctx.on_cleanup(lambda: cfn.delete_stack(StackName=stack_name))
    _wait_for_stack_status(ctx, stack_name, {"CREATE_COMPLETE"}, timeout_s=120)

    fetched = cfn.get_template(StackName=stack_name)
    parsed = json.loads(fetched["TemplateBody"]) if isinstance(fetched["TemplateBody"], str) else fetched["TemplateBody"]

    expected_description = description.encode("ascii", errors="replace").decode("ascii")
    expected_note = metadata["sim2real"]["note"].encode("ascii", errors="replace").decode("ascii")
    expected_arrow = metadata["sim2real"]["arrow"].encode("ascii", errors="replace").decode("ascii")

    assert parsed["Description"] == expected_description, (
        "Description did not match real AWS's ASCII-coercion contract: "
        + json.dumps(parsed["Description"], ensure_ascii=True)
        + " != "
        + json.dumps(expected_description, ensure_ascii=True)
    )
    assert parsed["Metadata"]["sim2real"]["note"] == expected_note, (
        "Metadata.note did not match real AWS's ASCII-coercion contract: "
        + json.dumps(parsed["Metadata"]["sim2real"]["note"], ensure_ascii=True)
        + " != "
        + json.dumps(expected_note, ensure_ascii=True)
    )
    assert parsed["Metadata"]["sim2real"]["arrow"] == expected_arrow, (
        "Metadata.arrow did not match real AWS's ASCII-coercion contract: "
        + json.dumps(parsed["Metadata"]["sim2real"]["arrow"], ensure_ascii=True)
        + " != "
        + json.dumps(expected_arrow, ensure_ascii=True)
    )
    # Guard against a fixture with no non-ASCII input, which would make the check vacuous.
    assert expected_description != description, (
        "test fixture bug: ASCII-folding the description produced no change, "
        "so the coercion contract this check exists to pin was never exercised"
    )
    assert any(ord(c) > 127 for c in description), (
        "test fixture bug: the description contains no non-ASCII code point, "
        "so the coercion contract this check exists to pin was never exercised"
    )


def _wait_for_stack_status(ctx, stack_name, terminal_statuses, timeout_s=120.0, interval_s=3.0):
    cfn = ctx.client("cloudformation")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        resp = cfn.describe_stacks(StackName=stack_name)
        last = resp["Stacks"][0]["StackStatus"]
        if last in terminal_statuses:
            return last
        time.sleep(interval_s)
    raise AssertionError(f"stack {stack_name} never reached {terminal_statuses}, last status {last}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
