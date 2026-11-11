"""update-stack-malformed-json-template-rejected."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "update-stack-malformed-json-template-rejected"
GROUP = "negative-classes"
SERVICES = ["cloudformation"]

_TEMPLATE_V1 = json.dumps(
    {
        "Resources": {
            "Topic": {
                "Type": "AWS::SNS::Topic",
                "Properties": {"DisplayName": "orig-display-name"},
            }
        }
    }
)

_TEMPLATE_V2 = json.dumps(
    {
        "Resources": {
            "Topic": {
                "Type": "AWS::SNS::Topic",
                "Properties": {"DisplayName": "updated-display-name"},
            }
        }
    }
)

# Syntactically invalid JSON: unterminated object/string.
_MALFORMED_JSON = '{"Resources": {"Topic": {"Type": "AWS::SNS::Topic", "Properties": {'


@tags("axis:rejection", "cap:c3", "cap:c4", "concern:deploy", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """UpdateStack with syntactically invalid JSON in TemplateBody is rejected before any
    resource mutation, and a syntactically valid UpdateStack on the same stack still works."""
    cfn = ctx.client("cloudformation")
    name = ctx.unique_name("sim2real-cfn-badjson-")
    cfn.create_stack(StackName=name, TemplateBody=_TEMPLATE_V1)
    ctx.on_cleanup(lambda: _safe_delete_stack(ctx, name))
    _wait_stack_status(ctx, name, {"CREATE_COMPLETE"})

    error = _error(lambda: cfn.update_stack(StackName=name, TemplateBody=_MALFORMED_JSON))
    # The parser reports the position just past the end of the truncated body.
    expected = ("ValidationError", "Template format error: YAML not well-formed. (line 1, column 68)")
    assert error == expected, f"expected {expected!r}, got {error!r}"

    # (b) effect absent: stack untouched, still on the original template/property value
    stacks = cfn.describe_stacks(StackName=name)["Stacks"]
    status = stacks[0]["StackStatus"]
    assert status == "CREATE_COMPLETE", f"rejected update mutated stack status: {status}"
    template = cfn.get_template(StackName=name)["TemplateBody"]
    display_name = template["Resources"]["Topic"]["Properties"]["DisplayName"]
    assert display_name == "orig-display-name", (
        f"rejected update changed the deployed template, DisplayName={display_name!r}"
    )

    # (c) positive control: a syntactically valid update on the same stack succeeds
    cfn.update_stack(StackName=name, TemplateBody=_TEMPLATE_V2)
    _wait_stack_status(ctx, name, {"UPDATE_COMPLETE"})
    template2 = cfn.get_template(StackName=name)["TemplateBody"]
    display_name2 = template2["Resources"]["Topic"]["Properties"]["DisplayName"]
    assert display_name2 == "updated-display-name", (
        f"expected the valid follow-up update to apply, DisplayName={display_name2!r}"
    )


def _error(fn):
    """Return the (code, message) of the ClientError ``fn`` raises; a success is a defect."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"expected the call to be refused, but it succeeded and returned {result!r}")


def _safe_delete_stack(ctx, name):
    cfn = ctx.client("cloudformation")
    try:
        cfn.delete_stack(StackName=name)
    except ClientError as exc:
        if not (
            exc.response["Error"]["Code"] == "ValidationError"
            and "does not exist" in exc.response["Error"].get("Message", "")
        ):
            raise


def _wait_stack_status(ctx, name, terminal_statuses, timeout_s=180.0, interval_s=3.0):
    cfn = ctx.client("cloudformation")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        stacks = cfn.describe_stacks(StackName=name)["Stacks"]
        last = stacks[0]["StackStatus"]
        if last in terminal_statuses:
            return last
        if last.endswith("FAILED") or "ROLLBACK" in last:
            raise AssertionError(f"stack {name} entered unexpected status {last}")
        time.sleep(interval_s)
    raise AssertionError(f"stack {name} never reached {terminal_statuses}, last={last}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
