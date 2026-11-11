"""changeset-duplicate-create-rejected."""
from __future__ import annotations

import json
import time
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "changeset-duplicate-create-rejected"
GROUP = 'change_sets'
SERVICES = ['cloudformation']


def _client_error(fn, what):
    """Return (code, message) of the ClientError `fn` raises; raise AssertionError if it succeeds."""
    try:
        fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected {what} to be rejected, but the call succeeded")


def _wait_changeset_status(cf, stack_name, cs_name, targets, timeout_s=120):
    deadline = time.monotonic() + timeout_s
    resp = cf.describe_change_set(StackName=stack_name, ChangeSetName=cs_name)
    while time.monotonic() < deadline:
        resp = cf.describe_change_set(StackName=stack_name, ChangeSetName=cs_name)
        if resp.get("Status") in targets:
            return resp
        time.sleep(2)
    raise AssertionError(
        f"change set {cs_name!r} did not reach {sorted(targets)} within {timeout_s}s "
        f"(last status {resp.get('Status')!r})"
    )

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


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A second CreateChangeSet(CREATE) reusing an existing stack and change set name with a different
    template is rejected with AlreadyExistsException and creates no second change set; once the
    first is deleted, the same call succeeds."""
    cf = ctx.client("cloudformation")
    name = ctx.unique_name("sim2real-behav-stack-cs-dup-")
    cs_name = ctx.unique_name("sim2real-behav-cs-dup-")

    cf.create_change_set(
        StackName=name,
        ChangeSetName=cs_name,
        ChangeSetType="CREATE",
        TemplateBody=_sns_template(),
    )
    ctx.on_cleanup(lambda: cf.delete_stack(StackName=name))
    _wait_changeset_status(cf, name, cs_name, {"CREATE_COMPLETE", "FAILED"})

    dup_call = lambda: cf.create_change_set(
        StackName=name,
        ChangeSetName=cs_name,
        ChangeSetType="CREATE",
        TemplateBody=_sns_template(tags={"x": "y"}),
    )
    dup_code, dup_msg = _client_error(dup_call, "a duplicate CreateChangeSet")
    assert dup_code == "AlreadyExistsException", dup_code
    assert dup_msg == (
        f"ChangeSet {cs_name} cannot be created due to a mismatch with existing attribute Template"
    ), dup_msg

    listed = cf.list_change_sets(StackName=name)["Summaries"]
    assert len([c for c in listed if c["ChangeSetName"] == cs_name]) == 1, listed

    # The rejection must track the live change set, not pin the name forever.
    cf.delete_change_set(StackName=name, ChangeSetName=cs_name)

    deleted_code, deleted_msg = _client_error(
        lambda: cf.describe_change_set(StackName=name, ChangeSetName=cs_name),
        "DescribeChangeSet of the deleted change set",
    )
    assert deleted_code == "ChangeSetNotFound", (
        f"expected the deleted change set to read back as not-found, got {deleted_code!r}"
    )
    assert deleted_msg == f"ChangeSet [{cs_name}] does not exist", deleted_msg

    dup_call()
    _wait_changeset_status(cf, name, cs_name, {"CREATE_COMPLETE", "FAILED"})
    relisted = cf.list_change_sets(StackName=name)["Summaries"]
    assert len([c for c in relisted if c["ChangeSetName"] == cs_name]) == 1, relisted

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
