"""op-contract-listExports."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "op-contract-listExports"
GROUP = "error-semantics"
SERVICES = ["cloudformation"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:deploy", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A stack Output with an Export shows up in the account-wide
    ListExports listing, pointing back at the exporting stack; an
    unrecognized NextToken is rejected with ValidationError."""
    cfn = ctx.client("cloudformation")
    stack_name = ctx.unique_name("sim2real-cfn-export-stack-")
    export_name = ctx.unique_name("sim2real-cfn-export-")

    template = json.dumps(
        {
            "Resources": {"Topic": {"Type": "AWS::SNS::Topic"}},
            "Outputs": {
                "TopicArn": {"Value": {"Ref": "Topic"}, "Export": {"Name": export_name}}
            },
        }
    )
    cfn.create_stack(StackName=stack_name, TemplateBody=template)
    ctx.on_cleanup(lambda: _delete_stack(ctx, stack_name))
    _wait_for_stack_status(ctx, stack_name, {"CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE"})

    found = _find_export(ctx, export_name)
    assert found is not None, f"export {export_name} not found via ListExports"
    assert stack_name in found["ExportingStackId"], found

    bogus_token = "sim2real-bogus-next-token-0000"
    code, message = _error(lambda: cfn.list_exports(NextToken=bogus_token))
    assert code == "ValidationError", f"expected ValidationError for bogus NextToken, got {code}"
    assert message == f"{bogus_token} is not a valid NextToken", (
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


def _find_export(ctx, export_name, max_pages=20):
    cfn = ctx.client("cloudformation")
    token = None
    for _ in range(max_pages):
        kwargs = {"NextToken": token} if token else {}
        resp = cfn.list_exports(**kwargs)
        for exp in resp.get("Exports", []):
            if exp.get("Name") == export_name:
                return exp
        token = resp.get("NextToken")
        if not token:
            break
    return None


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
