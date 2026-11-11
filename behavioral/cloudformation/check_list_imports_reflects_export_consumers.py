"""list-imports-reflects-export-consumers."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "list-imports-reflects-export-consumers"
GROUP = "ordering"
SERVICES = ["cloudformation"]

_STACK_TERMINAL = {"CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED"}


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:deploy", "plane:control")
def run(ctx) -> None:
    """ListImports for an export lists exactly the stacks currently importing it, consistent with ListExports."""
    cfn = ctx.client("cloudformation")
    export_name = ctx.unique_name("sim2real-export-")

    exporter_name = ctx.unique_name("sim2real-exporter-")
    exporter_template = {
        "Resources": {"Topic": {"Type": "AWS::SNS::Topic", "Properties": {"DisplayName": "exporter-topic"}}},
        "Outputs": {
            "TopicArn": {"Value": {"Ref": "Topic"}, "Export": {"Name": export_name}},
        },
    }
    exporter_id = cfn.create_stack(StackName=exporter_name, TemplateBody=json.dumps(exporter_template))["StackId"]
    ctx.on_cleanup(lambda: cfn.delete_stack(StackName=exporter_id))
    exporter_status = _wait_stack_terminal(cfn, exporter_id)
    assert exporter_status == "CREATE_COMPLETE", f"expected exporter CREATE_COMPLETE, got {exporter_status}"

    importer_name = ctx.unique_name("sim2real-importer-")
    importer_template = {
        "Resources": {
            "Queue": {
                "Type": "AWS::SQS::Queue",
                "Properties": {
                    "Tags": [{"Key": "importedFrom", "Value": {"Fn::ImportValue": export_name}}],
                },
            }
        }
    }
    importer_id = cfn.create_stack(StackName=importer_name, TemplateBody=json.dumps(importer_template))["StackId"]
    # register importer cleanup AFTER exporter cleanup so LIFO deletes the importer first (it holds the import)
    ctx.on_cleanup(lambda: cfn.delete_stack(StackName=importer_id))
    importer_status = _wait_stack_terminal(cfn, importer_id)
    assert importer_status == "CREATE_COMPLETE", f"expected importer CREATE_COMPLETE, got {importer_status}"

    exports = [e for page in cfn.get_paginator("list_exports").paginate() for e in page["Exports"]]
    matching = [e for e in exports if e["Name"] == export_name]
    assert len(matching) == 1, f"expected exactly one export named {export_name}, got {matching}"
    assert matching[0]["ExportingStackId"] == exporter_id, (
        f"expected ExportingStackId {exporter_id}, got {matching[0]['ExportingStackId']}"
    )

    imports = cfn.list_imports(ExportName=export_name)["Imports"]
    assert imports == [importer_name], f"expected exactly [{importer_name}], got {imports}"


def _wait_stack_terminal(cfn, stack_name: str, timeout_s: float = 180.0, interval_s: float = 3.0) -> str:
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        resp = cfn.describe_stacks(StackName=stack_name)
        stacks = resp.get("Stacks", [])
        if not stacks:
            return "DELETE_COMPLETE"
        status = stacks[0]["StackStatus"]
        if status in _STACK_TERMINAL:
            return status
        time.sleep(interval_s)
    raise AssertionError(f"stack {stack_name} did not reach terminal status within {timeout_s}s (last={status})")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
