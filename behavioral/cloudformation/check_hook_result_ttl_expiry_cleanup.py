"""hook-result-ttl-expiry-cleanup."""
from __future__ import annotations

import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "hook-result-ttl-expiry-cleanup"
GROUP = "state-machine"
SERVICES = ["cloudformation"]

_TEMPLATE = """{
  "Resources": {
    "Handle": {
      "Type": "AWS::CloudFormation::WaitConditionHandle"
    }
  }
}"""


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ListHookResults returns an empty page for a hook-less change set, before and after delete.

    GetHookResult on a never-issued id is HookResultNotFound, and the deleted change set is
    ChangeSetNotFound on DescribeChangeSet.
    """
    cfn = ctx.client("cloudformation")
    name = ctx.unique_name("sim2real-cfn-hookres-")
    cs_name = ctx.unique_name("sim2real-cfn-hookres-cs-")

    cs = cfn.create_change_set(
        StackName=name,
        ChangeSetName=cs_name,
        ChangeSetType="CREATE",
        TemplateBody=_TEMPLATE,
    )
    change_set_id = cs["Id"]
    ctx.on_cleanup(lambda: cfn.delete_change_set(ChangeSetName=change_set_id))
    ctx.on_cleanup(lambda: cfn.delete_stack(StackName=name))
    _wait_for_change_set_status(cfn, change_set_id, {"CREATE_COMPLETE", "FAILED"})

    # No Hook has ever been activated in this account, so this real, live ChangeSet
    # has zero Hook invocations recorded against it -- the target-scoped list must
    # come back as a normal, empty page.
    resp = cfn.list_hook_results(TargetType="CHANGE_SET", TargetId=change_set_id)
    assert resp["HookResults"] == [], f"expected no Hook results, got: {resp['HookResults']}"

    # A syntactically valid but never-issued HookResultId is unknown.
    bogus_result_id = str(uuid.uuid4())
    error = _client_error(lambda: cfn.get_hook_result(HookResultId=bogus_result_id))
    assert error.get("Code") == "HookResultNotFound", f"unexpected error: {error!r}"
    assert error.get("Message") == "The hook result was not found.", (
        f"expected message 'The hook result was not found.', got {error!r}"
    )

    cfn.delete_change_set(ChangeSetName=change_set_id)

    # The change set is gone: an independent read must reject it with the specific
    # not-found code, not merely stop returning it from a list.
    describe_error = _client_error(lambda: cfn.describe_change_set(ChangeSetName=change_set_id))
    assert describe_error.get("Code") == "ChangeSetNotFound", f"expected ChangeSetNotFound, got {describe_error!r}"
    expected_message = f"ChangeSet [{change_set_id}] does not exist"
    assert describe_error.get("Message") == expected_message, (
        f"expected message {expected_message!r}, got {describe_error!r}"
    )

    # Deleting the target does not conjure Hook history for a target that never had
    # any -- the same real ChangeSet ARN still comes back empty after it is gone.
    resp = cfn.list_hook_results(TargetType="CHANGE_SET", TargetId=change_set_id)
    assert resp["HookResults"] == [], f"expected no Hook results, got: {resp['HookResults']}"


def _client_error(fn):
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


def _wait_for_change_set_status(cfn, change_set_id, ok_statuses, timeout_s=120.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        try:
            resp = cfn.describe_change_set(ChangeSetName=change_set_id)
        except ClientError:
            time.sleep(2)
            continue
        last = resp.get("Status")
        if last in ok_statuses:
            return
        time.sleep(2)
    raise AssertionError(f"change set {change_set_id} never reached {ok_statuses}, last status={last}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
