"""op-contract-listChangeSets."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "op-contract-listChangeSets"
GROUP = "error-semantics"
SERVICES = ["cloudformation"]

_BUCKET_TEMPLATE = json.dumps({"Resources": {"Bucket": {"Type": "AWS::S3::Bucket"}}})


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListChangeSets surfaces a change set created against a new stack
    (ChangeSetType=CREATE) with the right status; listing change sets for a
    stack name that never existed is rejected with ValidationError."""
    cfn = ctx.client("cloudformation")
    stack_name = ctx.unique_name("sim2real-cfn-listcs-")
    cs_name = ctx.unique_name("sim2real-cfn-cs-")

    cfn.create_change_set(
        StackName=stack_name,
        ChangeSetName=cs_name,
        TemplateBody=_BUCKET_TEMPLATE,
        ChangeSetType="CREATE",
        Tags=[{"Key": "sim2real-audit", "Value": stack_name}],
    )
    ctx.on_cleanup(lambda: _delete_stack(ctx, stack_name))

    status = _wait_for_changeset_status(ctx, stack_name, cs_name, {"CREATE_COMPLETE", "FAILED"})
    assert status == "CREATE_COMPLETE", f"unexpected change set status {status}"

    summaries = cfn.list_change_sets(StackName=stack_name)["Summaries"]
    matching = [s for s in summaries if s["ChangeSetName"] == cs_name]
    assert len(matching) == 1, summaries
    assert matching[0]["Status"] == "CREATE_COMPLETE", matching[0]

    missing = ctx.unique_name("sim2real-cfn-missing-")
    code, message = _error(lambda: cfn.list_change_sets(StackName=missing))
    assert code == "ValidationError", f"expected ValidationError for unknown stack, got {code}"
    assert message == f"Stack [{missing}] does not exist", (
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


def _wait_for_changeset_status(
    ctx, stack_name, changeset_name, terminal_statuses, timeout_s=120.0, interval_s=3.0
):
    cfn = ctx.client("cloudformation")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        resp = cfn.describe_change_set(StackName=stack_name, ChangeSetName=changeset_name)
        last = resp["Status"]
        if last in terminal_statuses:
            return last
        time.sleep(interval_s)
    raise AssertionError(
        f"change set {changeset_name} did not reach {terminal_statuses} in {timeout_s}s (last={last})"
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
