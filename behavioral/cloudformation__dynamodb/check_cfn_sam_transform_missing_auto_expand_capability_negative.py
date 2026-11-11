"""cfn-sam-transform-missing-auto-expand-capability-negative."""

from __future__ import annotations

import time
from pathlib import Path
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-sam-transform-missing-auto-expand-capability-negative"

GROUP = "deployment-order"

SERVICES = ["cloudformation", "dynamodb"]

DEPLOYMENTS = Path(__file__).parent / "deployments"


@tags("axis:rejection", "cap:c3", "concern:deploy", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateStack of a Transform template without CAPABILITY_AUTO_EXPAND fails with
    InsufficientCapabilitiesException and creates neither the stack nor the table; the same call with
    the capability creates the ACTIVE table (positive control). Capabilities gate macro expansion."""
    cfn = ctx.client("cloudformation")
    ddb = ctx.client("dynamodb")

    template = (DEPLOYMENTS / "sam-simple-table-only.yaml").read_text()
    rejected_stack = _xname(ctx, "stk-noexpand")
    rejected_table = _xname(ctx, "sam-gated")

    # ---- negative leg: no CAPABILITY_AUTO_EXPAND ----
    code, message = _client_error(
        lambda: cfn.create_stack(
            StackName=rejected_stack,
            TemplateBody=template,
            Tags=_xsvc_tags_kv(),
            Parameters=[{"ParameterKey": "TableName", "ParameterValue": rejected_table}],
        ),
        f"create_stack {rejected_stack} for a Transform template without CAPABILITY_AUTO_EXPAND",
    )
    assert code == "InsufficientCapabilitiesException", f"create_stack {rejected_stack}: got {code!r}"
    assert message == "Requires capabilities : [CAPABILITY_AUTO_EXPAND]", (
        f"create_stack {rejected_stack}: got message {message!r}"
    )

    # The rejection must be total: no stack, and no partially expanded resource.
    code, message = _client_error(
        lambda: cfn.describe_stacks(StackName=rejected_stack),
        f"describe_stacks {rejected_stack} after a capability rejection",
    )
    assert code == "ValidationError", f"describe_stacks {rejected_stack}: got {code!r}"
    assert message == f"Stack with id {rejected_stack} does not exist", (
        f"describe_stacks {rejected_stack}: got message {message!r}"
    )
    code, message = _client_error(
        lambda: ddb.describe_table(TableName=rejected_table),
        f"describe_table {rejected_table} after a capability rejection",
    )
    assert code == "ResourceNotFoundException", f"describe_table {rejected_table}: got {code!r}"
    assert message == f"Requested resource not found: Table: {rejected_table} not found", (
        f"describe_table {rejected_table}: got message {message!r}"
    )

    # ---- control leg: the identical body, the identical parameters, capability added ----
    allowed_table = _xname(ctx, "sam-allowed")
    ctx.on_cleanup(lambda: _delete_table_if_present(ddb, allowed_table))
    result = _deploy_cfn(
        ctx,
        template,
        parameters={"TableName": allowed_table},
        capabilities=["CAPABILITY_AUTO_EXPAND"],
        timeout_s=900.0,
    )
    assert _outputs(result)["TableNameOut"] == allowed_table, _outputs(result)
    described = ddb.describe_table(TableName=allowed_table)["Table"]
    assert described["KeySchema"] == [{"AttributeName": "pk", "KeyType": "HASH"}], (
        described["KeySchema"]
    )
    assert described["TableStatus"] == "ACTIVE", described


_XSVC_PREFIX = "sim2real-xsvc-"

_MANAGED_TAG_KEY = "sim2real:managed"


def _xsvc_resource_tags() -> dict[str, str]:
    return {_MANAGED_TAG_KEY: "true", "sim2real:prefix": _XSVC_PREFIX.rstrip("-")}


def _xsvc_tags_kv() -> list[dict[str, str]]:
    return [{"Key": k, "Value": v} for k, v in _xsvc_resource_tags().items()]


def _xname(ctx: Any, kind: str) -> str:
    """A unique, prefix-tagged resource name: sim2real-xsvc-<kind>-<uuid>."""
    return ctx.unique_name(f"{_XSVC_PREFIX}{kind}-")


def _outputs(result: dict) -> dict:
    """Deployment results may nest outputs under 'outputs' or expose them flat."""
    return result.get("outputs", result)


def _poll_until(
    probe, predicate, *, timeout_s=60.0, interval_s=1.0, description="condition"
):
    """Poll probe() until predicate(result) is truthy; return the final result (raises on timeout)."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(
        f"{description} not met within {timeout_s}s. Last result: {last!r}"
    )


def _client_error(fn, description):
    """(Error.Code, Error.Message) of the ClientError fn() must raise; a success raises."""
    try:
        fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code", ""), error.get("Message")
    raise AssertionError(f"{description}: call unexpectedly succeeded")


def _delete_table_if_present(ddb, table_name: str) -> None:
    """Best-effort table teardown; a table the stack already removed is not an error."""
    try:
        ddb.delete_table(TableName=table_name)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise


def _delete_stack_and_wait(ctx, stack_name: str, *, timeout_s=600.0) -> None:
    """Delete a CFN stack and wait for DELETE_COMPLETE (teardown; errors swallowed by on_cleanup).

    timeout_s bounds the wait."""
    cfn = ctx.client("cloudformation")
    cfn.delete_stack(StackName=stack_name)

    def _status():
        try:
            return cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"]
        except ClientError as exc:
            if not (
                exc.response["Error"]["Code"] == "ValidationError"
                and "does not exist" in exc.response["Error"].get("Message", "")
            ):
                raise
            return "GONE"

    _poll_until(
        _status,
        lambda s: s in {"DELETE_COMPLETE", "GONE"},
        timeout_s=timeout_s,
        interval_s=5.0,
        description=f"delete stack {stack_name}",
    )


def _deploy_cfn(
    ctx,
    template,
    *,
    stack_name=None,
    parameters=None,
    capabilities=None,
    timeout_s=600.0,
) -> dict[str, Any]:
    """Deploy a CloudFormation stack (template body str or Path); wait for CREATE_COMPLETE;
    register delete-stack-and-wait teardown. Returns {stack_name,stack_id,outputs:{k:v}}."""
    ctx.verify_account_safety()
    cfn = ctx.client("cloudformation")
    name = stack_name or _xname(ctx, "stk")
    template_body = template.read_text() if isinstance(template, Path) else template
    kwargs: dict[str, Any] = {
        "StackName": name,
        "TemplateBody": template_body,
        "Tags": _xsvc_tags_kv(),
        "Capabilities": capabilities or ["CAPABILITY_IAM", "CAPABILITY_NAMED_IAM"],
    }
    if parameters:
        kwargs["Parameters"] = [
            {"ParameterKey": k, "ParameterValue": v} for k, v in parameters.items()
        ]
    stack_id = cfn.create_stack(**kwargs)["StackId"]
    ctx.on_cleanup(lambda: _delete_stack_and_wait(ctx, name, timeout_s=timeout_s))
    _poll_until(
        lambda: cfn.describe_stacks(StackName=name)["Stacks"][0]["StackStatus"],
        lambda s: (
            s
            in {
                "CREATE_COMPLETE",
                "CREATE_FAILED",
                "ROLLBACK_COMPLETE",
                "ROLLBACK_FAILED",
            }
        ),
        timeout_s=timeout_s,
        interval_s=5.0,
        description=f"CFN stack {name}",
    )
    stack = cfn.describe_stacks(StackName=name)["Stacks"][0]
    if stack["StackStatus"] != "CREATE_COMPLETE":
        raise AssertionError(f"Stack {name} ended in {stack['StackStatus']}")
    outputs = {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}
    return {"stack_name": name, "stack_id": stack_id, "outputs": outputs}


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
