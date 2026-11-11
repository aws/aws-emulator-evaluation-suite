"""changeset-hooks-not-found."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "changeset-hooks-not-found"
GROUP = "error-semantics"
SERVICES = ["cloudformation"]

_TEMPLATE = json.dumps(
    {
        "Resources": {
            "Topic": {"Type": "AWS::SNS::Topic", "Properties": {}},
        }
    }
)


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DescribeChangeSetHooks on a nonexistent change set returns ChangeSetNotFoundException."""
    cfn = ctx.client("cloudformation")
    stack_name = ctx.unique_name("sim2real-behav-cshooks-")
    cs_name = ctx.unique_name("sim2real-behav-cs-")
    bogus_cs_name = ctx.unique_name("sim2real-behav-nocs-")

    # Real CloudFormation validates that StackName refers to an existing stack *before* it looks
    # up the change set -- if StackName doesn't exist either, the request is rejected up front
    # with "ValidationError" (stack not found) and the change-set-not-found lookup this check
    # targets never happens. Use a real stack (with a real, non-executed change set on it) and
    # only make the ChangeSetName bogus, so the request passes stack validation and actually
    # exercises the not-found lookup for the change set itself.
    cfn.create_change_set(
        StackName=stack_name,
        ChangeSetName=cs_name,
        TemplateBody=_TEMPLATE,
        ChangeSetType="CREATE",
    )
    ctx.on_cleanup(lambda: cfn.delete_stack(StackName=stack_name))
    _wait_for_change_set_status(ctx, stack_name, cs_name, {"CREATE_COMPLETE"}, {"FAILED"})

    # Positive control: DescribeChangeSetHooks on the real change set must succeed and
    # describe *this* change set -- otherwise a target that rejects every
    # DescribeChangeSetHooks call (real or bogus) with ChangeSetNotFound would pass the
    # negative below for the wrong reason.
    real_resp = cfn.describe_change_set_hooks(ChangeSetName=cs_name, StackName=stack_name)
    assert real_resp["ChangeSetName"] == cs_name, (
        f"expected DescribeChangeSetHooks on the real change set to echo {cs_name!r}, "
        f"got {real_resp.get('ChangeSetName')!r}"
    )

    # Real CloudFormation reports this via the awsQuery error code "ChangeSetNotFound"
    # (no "Exception" suffix) -- a long-standing quirk of the ChangeSet-related error
    # family on the wire, distinct from the modeled exception class name.
    code, msg = _client_error(
        lambda: cfn.describe_change_set_hooks(
            ChangeSetName=bogus_cs_name, StackName=stack_name
        )
    )
    assert code == "ChangeSetNotFound", f"expected ChangeSetNotFound, got {code}"
    assert msg == f"ChangeSet [{bogus_cs_name}] does not exist", msg


def _client_error(fn):
    """Call fn(); return its error (code, message). An unexpected SUCCESS raises, because an
    emulator ACCEPTING input real AWS refuses is the strongest signal available."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


def _wait_for_change_set_status(ctx, stack_name, cs_name, terminal_ok, terminal_bad, timeout_s=120.0, interval_s=3.0):
    cfn = ctx.client("cloudformation")
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        resp = cfn.describe_change_set(StackName=stack_name, ChangeSetName=cs_name)
        status = resp["Status"]
        if status in terminal_ok or status in terminal_bad:
            break
        time.sleep(interval_s)
    if status not in terminal_ok:
        raise AssertionError(f"change set did not reach {terminal_ok}, ended at {status}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
