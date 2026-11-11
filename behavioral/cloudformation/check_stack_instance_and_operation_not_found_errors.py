"""stack-instance-and-operation-not-found-errors."""
from __future__ import annotations

import json
import time
import uuid
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "stack-instance-and-operation-not-found-errors"
GROUP = 'stack_sets'
SERVICES = ['cloudformation']


def _client_error(fn):
    """Call fn(); return (Error.Code, Error.Message) of the ClientError it raises. An
    unexpected success raises, so an accepting target never reads as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")

def _expect_error(fn, code, message):
    """Assert fn() raises a ClientError with exactly this code and message."""
    got_code, got_msg = _client_error(fn)
    assert got_code == code, f"expected {code}, got {got_code!r} ({got_msg!r})"
    assert got_msg == message, f"expected message {message!r}, got {got_msg!r}"

#: A documentation account id: no stack instance exists for it.
_FOREIGN_ACCOUNT = "111122223333"

def _sns_template(tags=None):
    props = {}
    if tags:
        props["Tags"] = [{"Key": k, "Value": v} for k, v in tags.items()]
    return json.dumps(
        {
            "Resources": {"Topic": {"Type": "AWS::SNS::Topic", "Properties": props}},
            "Outputs": {"TopicArn": {"Value": {"Ref": "Topic"}}},
        }
    )

def _wait_op_terminal(describe_fn, timeout_s=60, interval_s=2):
    """Poll describe_fn() -> Status until it is terminal; raise on timeout rather than
    returning the last (non-terminal) value."""
    terminal = {"SUCCEEDED", "FAILED", "STOPPED"}
    deadline = time.monotonic() + timeout_s
    status = describe_fn()
    while status not in terminal:
        if time.monotonic() >= deadline:
            raise TimeoutError(
                f"stack set operation did not reach a terminal state within {timeout_s}s "
                f"(last status={status!r})"
            )
        time.sleep(interval_s)
        status = describe_fn()
    return status


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Unknown StackSet/stack-instance/operation-id combinations raise
    StackInstanceNotFoundException, OperationNotFoundException, or
    StackSetNotFoundException as documented for each operation."""
    cf = ctx.client("cloudformation")
    missing_stackset = ctx.unique_name("sim2real-behav-stackset-missing-")
    fake_op_id = str(uuid.uuid4())
    fake_account = _FOREIGN_ACCOUNT

    _expect_error(
        lambda: cf.list_stack_instances(StackSetName=missing_stackset),
        "StackSetNotFoundException",
        f"StackSet {missing_stackset} not found",
    )
    _expect_error(
        lambda: cf.list_stack_set_operations(StackSetName=missing_stackset),
        "StackSetNotFoundException",
        f"StackSet {missing_stackset} not found",
    )
    _expect_error(
        lambda: cf.list_stack_set_auto_deployment_targets(StackSetName=missing_stackset),
        "StackSetNotFoundException",
        f"StackSet {missing_stackset} not found",
    )
    _expect_error(
        lambda: cf.describe_stack_instance(
            StackSetName=missing_stackset,
            StackInstanceAccount=fake_account,
            StackInstanceRegion=ctx.region,
        ),
        "StackSetNotFoundException",
        f"StackSet {missing_stackset} not found",
    )

    name = ctx.unique_name("sim2real-behav-stackset-ops-")
    cf.create_stack_set(
        StackSetName=name,
        TemplateBody=_sns_template(),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: cf.delete_stack_set(StackSetName=name))

    # Positive control: the same list/describe APIs succeed against a StackSet that really
    # exists, with the state (zero instances, zero operations so far) they in fact have. This
    # rules out a target that unconditionally raises StackSetNotFoundException for every call
    # regardless of whether the name is real.
    instances = cf.list_stack_instances(StackSetName=name)["Summaries"]
    assert instances == [], f"expected no stack instances yet, got {instances!r}"
    operations = cf.list_stack_set_operations(StackSetName=name)["Summaries"]
    assert operations == [], f"expected no operations yet, got {operations!r}"

    # ListStackSetAutoDeploymentTargets requires a SERVICE_MANAGED stack set; this one is
    # SELF_MANAGED (the default), so real AWS rejects it with ValidationError -- a different,
    # more specific error than the StackSetNotFoundException asserted above against a name
    # that does not exist at all. This still rules out a target that answers
    # StackSetNotFoundException unconditionally: it must tell "exists but self-managed" apart
    # from "does not exist".
    auto_deploy_code, auto_deploy_msg = _client_error(
        lambda: cf.list_stack_set_auto_deployment_targets(StackSetName=name)
    )
    assert auto_deploy_code == "ValidationError", (
        f"expected ValidationError (auto-deployment targets need a service-managed stack "
        f"set), got {auto_deploy_code!r}"
    )
    assert auto_deploy_msg == (
        "Auto-deployment targets are only available for service-managed stack sets"
    ), auto_deploy_msg

    _expect_error(
        lambda: cf.describe_stack_instance(
            StackSetName=name,
            StackInstanceAccount=fake_account,
            StackInstanceRegion=ctx.region,
        ),
        "StackInstanceNotFoundException",
        "StackInstance not found",
    )

    # Positive control for the operation-scoped APIs below: a real OperationId (from updating
    # the StackSet, which has zero deployed instances to fan out to and so completes on its
    # own) must be describable and listable. This rules out a target that unconditionally
    # raises OperationNotFoundException for every OperationId regardless of whether it is real.
    real_op_id = cf.update_stack_set(
        StackSetName=name, TemplateBody=_sns_template({"probe": "positive-control"})
    )["OperationId"]
    final_status = _wait_op_terminal(
        lambda: cf.describe_stack_set_operation(StackSetName=name, OperationId=real_op_id)[
            "StackSetOperation"
        ]["Status"]
    )
    assert final_status == "SUCCEEDED", (
        f"expected UpdateStackSet with zero stack instances to complete as SUCCEEDED, "
        f"got {final_status!r}"
    )
    op_results = cf.list_stack_set_operation_results(StackSetName=name, OperationId=real_op_id)[
        "Summaries"
    ]
    assert op_results == [], f"expected no per-instance results (zero instances), got {op_results!r}"

    _expect_error(
        lambda: cf.describe_stack_set_operation(StackSetName=name, OperationId=fake_op_id),
        "OperationNotFoundException",
        "Operation not found",
    )
    _expect_error(
        lambda: cf.list_stack_set_operation_results(StackSetName=name, OperationId=fake_op_id),
        "OperationNotFoundException",
        "Operation not found",
    )
    _expect_error(
        lambda: cf.stop_stack_set_operation(StackSetName=name, OperationId=fake_op_id),
        "OperationNotFoundException",
        "Operation not found",
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
