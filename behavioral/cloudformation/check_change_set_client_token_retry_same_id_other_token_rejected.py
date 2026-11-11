"""change-set-client-token-retry-same-id-other-token-rejected."""
from __future__ import annotations

import json
import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "change-set-client-token-retry-same-id-other-token-rejected"
GROUP = "change_sets"
SERVICES = ["cloudformation"]

_TAGS = [{"Key": "sim2real", "Value": CHECK}]
_TEMPLATE = json.dumps({"Resources": {"Handle": {"Type": "AWS::CloudFormation::WaitConditionHandle"}}})
_ARN = re.compile(r"^arn:[a-z-]+:cloudformation:[a-z0-9-]+:[0-9]{12}:changeSet/([^/]+)/"
                  r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")


def _error(fn):
    """(code, message) of the ClientError fn() raises; a success raises AssertionError."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message")
    raise AssertionError(f"expected a refusal, the call succeeded: {result!r}")


def _cap(ctx, own_s, margin_s=15.0):
    """Bound a wait by the check's remaining budget."""
    left = ctx.time_left()
    return own_s if left is None else max(1.0, min(own_s, left - margin_s))


def _wait_change_set(cf, cs_id, *, timeout_s=180.0, **extra):
    """Poll DescribeChangeSet until CREATE_COMPLETE or FAILED; return the description."""
    deadline = time.monotonic() + timeout_s
    while True:
        cs = cf.describe_change_set(ChangeSetName=cs_id, **extra)
        if cs["Status"] in ("CREATE_COMPLETE", "FAILED"):
            return cs
        if time.monotonic() > deadline:
            raise AssertionError(f"change set still {cs['Status']!r} after {timeout_s}s")
        time.sleep(3)


def _delete_stack(cf, stack_id, *, timeout_s=600.0):
    """Delete a stack by id and poll until DELETE_COMPLETE; DELETE_FAILED or a timeout raises."""
    cf.delete_stack(StackName=stack_id)
    deadline = time.monotonic() + timeout_s
    while True:
        stack = cf.describe_stacks(StackName=stack_id)["Stacks"][0]
        if stack["StackStatus"] in ("DELETE_COMPLETE", "DELETE_FAILED"):
            break
        if time.monotonic() > deadline:
            raise RuntimeError(f"stack {stack_id} still {stack['StackStatus']!r} after {timeout_s}s")
        time.sleep(3)
    if stack["StackStatus"] != "DELETE_COMPLETE":
        raise RuntimeError(f"stack {stack_id} ended {stack['StackStatus']!r}: "
                           f"{stack.get('StackStatusReason')!r}")


def _by_logical_id(cs):
    """The change set's ResourceChange entries keyed by LogicalResourceId."""
    return {c["ResourceChange"]["LogicalResourceId"]: c["ResourceChange"] for c in cs["Changes"]}

@tags("axis:rejection", "cap:c1", "concern:deploy", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A CreateChangeSet retried with the same ClientToken returns the same change set Id; the same
    name with another token is refused with the exact AlreadyExistsException, and one set exists.

    Reference: https://docs.aws.amazon.com/AWSCloudFormation/latest/APIReference/API_CreateChangeSet.html
    """
    cf = ctx.client("cloudformation")
    stack_name = ctx.unique_name("sim2real-behav-cstok-")
    cs_name = ctx.unique_name("sim2real-behav-cstok-cs-")
    token = ctx.unique_name("sim2real-tok-")

    def create(client_token):
        return cf.create_change_set(StackName=stack_name, ChangeSetName=cs_name,
                                    ChangeSetType="CREATE", TemplateBody=_TEMPLATE, Tags=_TAGS,
                                    ClientToken=client_token)

    first = create(token)
    stack_id = first["StackId"]
    ctx.on_cleanup(lambda: _delete_stack(cf, stack_id))
    match = _ARN.match(first["Id"])
    assert match and match.group(1) == cs_name, f"change set Id form: {first['Id']!r}"

    retry = create(token)
    assert (retry["Id"], retry["StackId"]) == (first["Id"], stack_id), (
        f"a retry with the same ClientToken must return the same change set, got {retry!r}")

    got = _error(lambda: create(ctx.unique_name("sim2real-tok-")))
    assert got == (
        "AlreadyExistsException",
        f"ChangeSet {cs_name} cannot be created due to a mismatch with existing attribute "
        f"ClientToken",
    ), f"same name, other ClientToken answered {got!r}"

    listed = [s["ChangeSetId"] for s in cf.list_change_sets(StackName=stack_id)["Summaries"]]
    assert listed == [first["Id"]], f"exactly the one change set must exist, got {listed!r}"
    cs = _wait_change_set(cf, first["Id"], timeout_s=_cap(ctx, 180.0))
    assert cs["Status"] == "CREATE_COMPLETE", f"change set: {cs.get('StatusReason')!r}"
    assert sorted(_by_logical_id(cs)) == ["Handle"], cs["Changes"]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
