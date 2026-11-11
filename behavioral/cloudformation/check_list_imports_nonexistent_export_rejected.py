"""list-imports-nonexistent-export-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-imports-nonexistent-export-rejected"
GROUP = "ordering"
SERVICES = ["cloudformation"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ListImports fails with ValidationError "Export '<name>' does not exist." for an export name that
    never existed and "Export '<name>' is not imported by any stack." for an export with no importer,
    and returns exactly the importing stack once one imports the export."""
    cfn = ctx.client("cloudformation")

    export_name = ctx.unique_name("sim2real-export-")
    exporter_name = ctx.unique_name("sim2real-cfn-exporter-")
    exporter_template = json.dumps(
        {
            "Resources": {"Topic": {"Type": "AWS::SNS::Topic"}},
            "Outputs": {"TopicArn": {"Value": {"Ref": "Topic"}, "Export": {"Name": export_name}}},
        }
    )
    cfn.create_stack(
        StackName=exporter_name,
        TemplateBody=exporter_template,
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    # Registered first so it runs LAST (LIFO) -- the importer must be deleted
    # before the exporter can be deleted (an in-use export cannot be removed).
    ctx.on_cleanup(lambda: _delete_stack(ctx, exporter_name))
    status = _wait_for_stack_status(ctx, exporter_name, {"CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE"})
    assert status == "CREATE_COMPLETE", f"exporter stack did not create cleanly: {status}"

    # An export with zero importers is also a ValidationError ("is not imported by any
    # stack"), so the negative below is told apart by its message, not just its code.
    unimported_code, unimported_msg = _error_code_and_message(lambda: cfn.list_imports(ExportName=export_name))
    assert unimported_code == "ValidationError", f"expected ValidationError for a zero-importer export, got {unimported_code}"
    expected_unimported = f"Export '{export_name}' is not imported by any stack."
    assert unimported_msg == expected_unimported, f"expected message {expected_unimported!r}, got {unimported_msg!r}"

    importer_name = ctx.unique_name("sim2real-cfn-importer-")
    importer_template = json.dumps(
        {
            "Resources": {
                "Param": {
                    "Type": "AWS::SSM::Parameter",
                    "Properties": {"Type": "String", "Value": {"Fn::ImportValue": export_name}},
                }
            }
        }
    )
    cfn.create_stack(
        StackName=importer_name,
        TemplateBody=importer_template,
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _delete_stack(ctx, importer_name))
    status = _wait_for_stack_status(ctx, importer_name, {"CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE"})
    assert status == "CREATE_COMPLETE", f"importer stack did not create cleanly: {status}"

    imports = cfn.list_imports(ExportName=export_name)["Imports"]
    assert imports == [importer_name], f"expected exactly [{importer_name}], got {imports}"

    bogus_export_name = ctx.unique_name("sim2real-no-such-export-")
    bogus_code, bogus_msg = _error_code_and_message(lambda: cfn.list_imports(ExportName=bogus_export_name))
    assert bogus_code == "ValidationError", f"expected ValidationError, got {bogus_code}"
    expected_bogus = f"Export '{bogus_export_name}' does not exist."
    assert bogus_msg == expected_bogus, f"expected message {expected_bogus!r}, got {bogus_msg!r}"


def _error_code_and_message(fn):
    try:
        fn()
    except ClientError as exc:
        error = exc.response["Error"]
        return error["Code"], error.get("Message", "")
    raise AssertionError("expected ListImports to raise, it returned normally")


def _wait_for_stack_status(ctx, stack_name, terminal_statuses, timeout_s=180.0, interval_s=3.0):
    cfn = ctx.client("cloudformation")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        resp = cfn.describe_stacks(StackName=stack_name)
        last = resp["Stacks"][0]["StackStatus"]
        if last in terminal_statuses:
            return last
        time.sleep(interval_s)
    raise AssertionError(
        f"stack {stack_name} did not reach {terminal_statuses} in {timeout_s}s (last={last})"
    )


def _delete_stack(ctx, stack_name):
    cfn = ctx.client("cloudformation")
    try:
        cfn.delete_stack(StackName=stack_name)
    except ClientError as exc:
        if not (
            exc.response["Error"]["Code"] == "ValidationError"
            and "does not exist" in exc.response["Error"].get("Message", "")
        ):
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
