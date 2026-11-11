"""cfn-delete-exporting-stack-rejected-while-import-exists."""

from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-delete-exporting-stack-rejected-while-import-exists"

GROUP = "deploy_exports"

SERVICES = ["cloudformation", "sqs", "ssm"]


def _exporter_template(queue_name: str, export_name: str) -> str:
    return json.dumps({
        "Resources": {
            "Exported": {"Type": "AWS::SQS::Queue",
                         "Properties": {"QueueName": queue_name, "VisibilityTimeout": 30}},
        },
        "Outputs": {
            "QueueUrl": {"Value": {"Ref": "Exported"}, "Export": {"Name": export_name}},
        },
    })


def _importer_template(param_name: str, export_name: str) -> str:
    """Importer template with the export name inlined, since Fn::ImportValue over a Ref is
    restricted by CloudFormation."""
    return json.dumps({
        "Resources": {
            "Holder": {"Type": "AWS::SSM::Parameter",
                       "Properties": {"Name": param_name, "Type": "String",
                                      "Value": {"Fn::ImportValue": export_name}}},
        },
    })


@tags("axis:rejection", "cap:c3", "concern:data-plane", "concern:e2e", "concern:eventing",
      "concern:negative-classes", "dp:api", "plane:control", "plane:data")
def run(ctx) -> None:
    """An export in use pins its stack: the delete is cancelled and the stack returns to
    CREATE_COMPLETE, the exported queue still works, and the identical delete succeeds once the
    importer is gone.
    """
    cfn = ctx.client("cloudformation")
    sqs = ctx.client("sqs")
    ssm = ctx.client("ssm")

    queue_name = _xname(ctx, "exp-q")
    export_name = _xname(ctx, "exp-name")
    param_name = "/" + _xname(ctx, "exp-p")
    # Registered before stack A exists: an abandoned stack strands everything inside it.
    ctx.on_cleanup(lambda: _delete_queue_by_name_if_present(sqs, queue_name))
    ctx.on_cleanup(lambda: _delete_parameter_if_present(ssm, param_name))

    stack_a, status_a = _create_stack_and_wait(
        ctx, _exporter_template(queue_name, export_name),
        stack_name=_xname(ctx, "exp-a"), timeout_s=600.0)
    assert status_a == "CREATE_COMPLETE", f"the exporting stack ended in {status_a!r}"
    queue_url = _outputs(cfn, stack_a)["QueueUrl"]

    stack_b, status_b = _create_stack_and_wait(
        ctx, _importer_template(param_name, export_name),
        stack_name=_xname(ctx, "exp-b"), timeout_s=600.0)
    assert status_b == "CREATE_COMPLETE", f"the importing stack ended in {status_b!r}"

    # 1. The import resolved to the real resource, not to a placeholder, and CloudFormation
    #    records the pin in both directions.
    resolved = ssm.get_parameter(Name=param_name)["Parameter"]["Value"]
    assert resolved == queue_url, (
        f"Fn::ImportValue did not resolve to the exported queue URL: {resolved!r} vs "
        f"{queue_url!r}"
    )
    assert cfn.list_imports(ExportName=export_name)["Imports"] == [stack_b], (
        f"ListImports must name the importing stack, got "
        f"{cfn.list_imports(ExportName=export_name)['Imports']!r}"
    )

    # ---- the delete the export must refuse ----
    cfn.delete_stack(StackName=stack_a)
    # DeleteStack returns 200; the stack enters DELETE_IN_PROGRESS, then CloudFormation cancels
    # the delete and returns it to CREATE_COMPLETE (not DELETE_FAILED). So wait for the attempt
    # to finish, separately from the verdict asserted below.
    _poll_until(lambda: _delete_attempt_finished(cfn, stack_a), bool,
                timeout_s=300.0, interval_s=5.0,
                description=f"the delete attempt on the exporting stack {stack_a} to resolve")
    refused = _stack_status(cfn, stack_a)
    assert refused == "CREATE_COMPLETE", (
        f"an in-use export must CANCEL the delete and leave the stack healthy, got {refused!r}"
    )

    # 2. CloudFormation must say the export is in use, and name the importing stack.
    blob = _failure_text(cfn, stack_a)
    assert "Delete canceled" in blob, (
        f"CloudFormation must record that it cancelled the delete; reasons were {blob!r}"
    )
    assert export_name in blob, (
        f"the cancellation reason must name the export {export_name!r}; got {blob!r}"
    )
    assert stack_b in blob, (
        f"the cancellation reason must name the importing stack {stack_b!r}; got {blob!r}"
    )

    # 3. The effect is ABSENT: nothing was destroyed, and the queue still works.
    marker = f"pinned-{queue_name}"
    sqs.send_message(QueueUrl=queue_url, MessageBody=marker)
    received = _receive_one(sqs, queue_url, timeout_s=180.0)
    assert received["Body"] == marker, (
        f"the pinned queue must still work after the refused delete: {received!r}"
    )

    # ---- Control: remove the importer, then the identical delete must succeed ----
    _delete_stack_and_wait(ctx, stack_b, timeout_s=600.0)
    assert _stack_status(cfn, stack_b) in {"DELETE_COMPLETE", "GONE"}, (
        f"the importing stack did not delete: {_stack_status(cfn, stack_b)!r}"
    )
    assert export_name in _exports(cfn), (
        f"export {export_name!r} disappeared when the IMPORTING stack was deleted; it belongs to "
        f"stack A, so the second delete below would not be testing the same thing"
    )

    cfn.delete_stack(StackName=stack_a)
    final_a = _poll_until(lambda: _stack_status(cfn, stack_a),
                          lambda s: s in {"DELETE_COMPLETE", "GONE", "DELETE_FAILED"},
                          timeout_s=600.0, interval_s=5.0,
                          description=f"second delete of {stack_a}")
    assert final_a in {"DELETE_COMPLETE", "GONE"}, (
        f"after deleting the importer, stack A must delete cleanly; last status was {final_a!r}"
    )
    # And the export it held is gone with it, so nothing is left pinning anything.
    assert export_name not in _exports(cfn), (
        f"export {export_name!r} outlived the stack that declared it"
    )


_XSVC_PREFIX = "sim2real-xsvc-"

_NO_SUCH_QUEUE = "AWS.SimpleQueueService.NonExistentQueue"

_CREATE_TERMINAL = {"CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED",
                    "DELETE_COMPLETE", "DELETE_FAILED", "GONE"}


def _xname(ctx: Any, kind: str) -> str:
    """A unique, prefix-tagged resource name: sim2real-xsvc-<kind>-<uuid>."""
    return ctx.unique_name(f"{_XSVC_PREFIX}{kind}-")


def _tags_kv() -> list[dict[str, str]]:
    return [{"Key": "sim2real:managed", "Value": "true"},
            {"Key": "sim2real:prefix", "Value": _XSVC_PREFIX.rstrip("-")}]


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=1.0, description="condition"):
    """Poll probe() until predicate(result) is truthy; return the final result (raises on timeout)."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _queue_url_or_none(sqs, name: str) -> str | None:
    try:
        return sqs.get_queue_url(QueueName=name)["QueueUrl"]
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == _NO_SUCH_QUEUE:
            return None
        raise


def _delete_queue_by_name_if_present(sqs, name: str) -> None:
    """Best-effort queue teardown by name; already-deleted is not an error."""
    url = _queue_url_or_none(sqs, name)
    if url:
        sqs.delete_queue(QueueUrl=url)


def _delete_parameter_if_present(ssm, name: str) -> None:
    """Best-effort SSM parameter teardown; already-deleted is not an error."""
    try:
        ssm.delete_parameter(Name=name)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ParameterNotFound":
            raise


def _receive_one(sqs, url: str, *, timeout_s=120.0) -> dict[str, Any]:
    """Long-poll a queue until one message arrives; return it (raises on timeout)."""
    msgs = _poll_until(
        lambda: sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=1,
                                    WaitTimeSeconds=20).get("Messages", []),
        bool, timeout_s=timeout_s, interval_s=1.0, description=f"a message on {url}")
    return msgs[0]


def _stack_status(cfn, name: str) -> str:
    try:
        return cfn.describe_stacks(StackName=name)["Stacks"][0]["StackStatus"]
    except ClientError as err:
        if "does not exist" in str(err):
            return "GONE"
        raise


def _outputs(cfn, name: str) -> dict[str, str]:
    stack = cfn.describe_stacks(StackName=name)["Stacks"][0]
    return {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}


def _exports(cfn) -> dict[str, str]:
    """Every export in this account+region, paginated. The namespace is account-global, which is
    why the export name here comes from ctx.unique_name."""
    out: dict[str, str] = {}
    for page in cfn.get_paginator("list_exports").paginate():
        for e in page.get("Exports", []):
            out[e["Name"]] = e["Value"]
    return out


def _stack_events(cfn, name: str) -> list[dict[str, Any]]:
    """Every event for a stack, oldest first, paginated."""
    events: list[dict[str, Any]] = []
    token = None
    while True:
        kwargs: dict[str, Any] = {"StackName": name}
        if token:
            kwargs["NextToken"] = token
        page = cfn.describe_stack_events(**kwargs)
        events.extend(page.get("StackEvents", []))
        token = page.get("NextToken")
        if not token:
            break
    return list(reversed(events))


def _delete_attempt_finished(cfn, name: str) -> bool:
    """True once a user-initiated DeleteStack has been logged and is no longer in progress."""
    if _stack_status(cfn, name) == "DELETE_IN_PROGRESS":
        return False
    return any(e.get("ResourceStatus") == "DELETE_IN_PROGRESS"
               and e.get("LogicalResourceId") == name
               for e in _stack_events(cfn, name))


def _failure_text(cfn, name: str) -> str:
    """Every event reason for a stack plus its StackStatusReason, joined; the in-use-export
    refusal text is not pinned to one field."""
    parts = [e.get("ResourceStatusReason") or "" for e in _stack_events(cfn, name)]
    try:
        parts.append(cfn.describe_stacks(StackName=name)["Stacks"][0].get("StackStatusReason") or "")
    except ClientError:
        pass
    return " | ".join(p for p in parts if p)


def _delete_stack_and_wait(ctx, name: str, *, timeout_s=900.0) -> None:
    """Delete a stack and wait for it to go; a failed delete raises."""
    cfn = ctx.client("cloudformation")
    cfn.delete_stack(StackName=name)
    final = _poll_until(lambda: _stack_status(cfn, name),
                        lambda s: s in {"DELETE_COMPLETE", "GONE", "DELETE_FAILED"},
                        timeout_s=timeout_s, interval_s=2.0,
                        description=f"delete stack {name}")
    if final == "DELETE_FAILED":
        raise RuntimeError(f"stack {name} ended DELETE_FAILED; its resources are stranded")


def _create_stack_and_wait(ctx, template: str, *, stack_name=None, parameters=None,
                           capabilities=None, timeout_s=900.0) -> tuple[str, str]:
    """create_stack, then poll to a terminal status which is RETURNED rather than asserted."""
    cfn = ctx.client("cloudformation")
    ctx.verify_account_safety()
    name = stack_name or _xname(ctx, "stk")
    kwargs: dict[str, Any] = {
        "StackName": name, "TemplateBody": template, "Tags": _tags_kv(),
        "Capabilities": capabilities or ["CAPABILITY_IAM", "CAPABILITY_NAMED_IAM"],
    }
    if parameters:
        kwargs["Parameters"] = [{"ParameterKey": k, "ParameterValue": v}
                                for k, v in parameters.items()]
    cfn.create_stack(**kwargs)
    ctx.on_cleanup(lambda: _delete_stack_and_wait(ctx, name, timeout_s=timeout_s))
    status = _poll_until(lambda: _stack_status(cfn, name), lambda s: s in _CREATE_TERMINAL,
                         timeout_s=timeout_s, interval_s=5.0,
                         description=f"create stack {name}")
    return name, status


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
