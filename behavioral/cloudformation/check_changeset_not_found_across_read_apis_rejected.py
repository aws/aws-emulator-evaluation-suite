"""changeset-not-found-across-read-apis-rejected."""
from __future__ import annotations

import json
import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "changeset-not-found-across-read-apis-rejected"
GROUP = "error-semantics"
SERVICES = ["cloudformation"]

_TEMPLATE = json.dumps({"Resources": {"Topic": {"Type": "AWS::SNS::Topic", "Properties": {}}}})


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DescribeChangeSet, DescribeChangeSetHooks, GetTemplate and ExecuteChangeSet all reject a
    nonexistent change set ARN with ChangeSetNotFound and the same message, after the same four
    calls succeed against a real change set."""
    cfn = ctx.client("cloudformation")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    stack_name = ctx.unique_name("sim2real-cs-notfound-")
    ctx.on_cleanup(lambda: cfn.delete_stack(StackName=stack_name))
    cs_name = ctx.unique_name("sim2real-cs-")
    real_cs_arn = cfn.create_change_set(
        StackName=stack_name,
        ChangeSetName=cs_name,
        ChangeSetType="CREATE",
        TemplateBody=_TEMPLATE,
    )["Id"]
    _wait_change_set_status(cfn, real_cs_arn, {"CREATE_COMPLETE"}, {"FAILED"})

    described = cfn.describe_change_set(ChangeSetName=real_cs_arn)
    assert described["Status"] == "CREATE_COMPLETE", (
        f"positive control: DescribeChangeSet({real_cs_arn}) expected CREATE_COMPLETE, "
        f"got {described.get('Status')!r}"
    )
    hooks = cfn.describe_change_set_hooks(ChangeSetName=real_cs_arn)
    assert isinstance(hooks.get("Hooks"), list), (
        f"positive control: DescribeChangeSetHooks({real_cs_arn}) did not return a Hooks "
        f"list: {hooks!r}"
    )
    real_template = cfn.get_template(ChangeSetName=real_cs_arn)
    body = real_template["TemplateBody"]
    parsed = json.loads(body) if isinstance(body, str) else body
    assert "Topic" in parsed.get("Resources", {}), (
        f"positive control: GetTemplate({real_cs_arn}) did not return the change set's "
        f"own template: {real_template!r}"
    )
    cfn.execute_change_set(ChangeSetName=real_cs_arn)
    exec_status = _wait_stack_status(
        cfn, stack_name, {"CREATE_COMPLETE"}, {"CREATE_FAILED", "ROLLBACK_COMPLETE"}
    )
    assert exec_status == "CREATE_COMPLETE", (
        f"positive control: ExecuteChangeSet({real_cs_arn}) expected stack CREATE_COMPLETE, "
        f"got {exec_status!r}"
    )

    bogus_arn = (
        f"arn:aws:cloudformation:{ctx.region}:{account_id}:changeSet/"
        f"{ctx.unique_name('sim2real-cs-')}/{uuid.uuid4()}"
    )

    checks = [
        ("DescribeChangeSet", lambda: cfn.describe_change_set(ChangeSetName=bogus_arn)),
        ("DescribeChangeSetHooks", lambda: cfn.describe_change_set_hooks(ChangeSetName=bogus_arn)),
        ("GetTemplate", lambda: cfn.get_template(ChangeSetName=bogus_arn)),
        ("ExecuteChangeSet", lambda: cfn.execute_change_set(ChangeSetName=bogus_arn)),
    ]
    # The wire code is "ChangeSetNotFound" although the modeled shape is ChangeSetNotFoundException.
    for label, fn in checks:
        code, msg = _client_error(label, fn)
        assert code == "ChangeSetNotFound", f"{label} returned {code!r}, expected ChangeSetNotFound"
        assert msg == f"ChangeSet [{bogus_arn}] does not exist", f"{label}: {msg!r}"


def _client_error(label, fn):
    """Return (code, message) of the ClientError `fn` raises; raise AssertionError if it succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"{label}(<nonexistent change set arn>) unexpectedly SUCCEEDED: {result!r}")


def _wait_change_set_status(cfn, cs_arn, terminal_ok, terminal_bad, timeout_s=120.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        status = cfn.describe_change_set(ChangeSetName=cs_arn)["Status"]
        if status in terminal_ok or status in terminal_bad:
            break
        time.sleep(interval_s)
    if status not in terminal_ok:
        raise AssertionError(f"change set {cs_arn} did not reach {terminal_ok}, ended at {status!r}")
    return status


def _wait_stack_status(cfn, stack_name, terminal_ok, terminal_bad, timeout_s=180.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        status = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"]
        if status in terminal_ok or status in terminal_bad:
            break
        time.sleep(interval_s)
    if status not in terminal_ok:
        raise AssertionError(f"stack {stack_name} did not reach {terminal_ok}, ended at {status!r}")
    return status


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
