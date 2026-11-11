"""op-contract-listImports."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "op-contract-listImports"
GROUP = "error-semantics"
SERVICES = ["cloudformation"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:deploy", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A stack that Fn::ImportValue's another stack's export shows up in
    ListImports for that ExportName; listing imports for a name that is not
    currently exported is rejected with ValidationError."""
    cfn = ctx.client("cloudformation")
    exporter_name = ctx.unique_name("sim2real-cfn-exporter-")
    importer_name = ctx.unique_name("sim2real-cfn-importer-")
    export_name = ctx.unique_name("sim2real-cfn-export-")

    exporter_template = json.dumps(
        {
            "Resources": {"Topic": {"Type": "AWS::SNS::Topic"}},
            "Outputs": {
                "TopicArn": {"Value": {"Ref": "Topic"}, "Export": {"Name": export_name}}
            },
        }
    )
    cfn.create_stack(
        StackName=exporter_name,
        TemplateBody=exporter_template,
        Tags=[{"Key": "owner", "Value": "fidelity"}],
    )
    # Registered first so it runs LAST (LIFO) -- the importer must be deleted
    # before the exporter can be deleted (an in-use export cannot be removed).
    ctx.on_cleanup(lambda: _delete_stack(ctx, exporter_name))
    _wait_for_stack_status(ctx, exporter_name, {"CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE"})

    importer_template = json.dumps(
        {
            "Resources": {
                "Param": {
                    "Type": "AWS::SSM::Parameter",
                    "Properties": {
                        "Type": "String",
                        "Value": {"Fn::ImportValue": export_name},
                    },
                }
            }
        }
    )
    cfn.create_stack(
        StackName=importer_name,
        TemplateBody=importer_template,
        Tags=[{"Key": "owner", "Value": "fidelity"}],
    )
    ctx.on_cleanup(lambda: _delete_stack(ctx, importer_name))
    _wait_for_stack_status(ctx, importer_name, {"CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE"})

    imports = cfn.list_imports(ExportName=export_name)["Imports"]
    # export_name is unique to this run, so the importer stack above is the only possible consumer.
    assert imports == [importer_name], f"expected exactly [{importer_name}], got {imports}"

    not_exported = ctx.unique_name("sim2real-cfn-noexport-")
    code, message = _error(lambda: cfn.list_imports(ExportName=not_exported))
    assert code == "ValidationError", f"expected ValidationError for a non-exported name, got {code}"
    assert message == f"Export '{not_exported}' does not exist.", (
        f"unexpected ValidationError message {message!r}"
    )


def _error(fn):
    """Call fn(); return botocore (Error.Code, Error.Message). An unexpected SUCCESS raises, because
    an emulator ACCEPTING input real AWS refuses is the strongest signal available."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        err = e.response["Error"]
        return err["Code"], err.get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


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
