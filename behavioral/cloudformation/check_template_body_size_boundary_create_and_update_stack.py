"""template-body-size-boundary-create-and-update-stack."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "template-body-size-boundary-create-and-update-stack"
GROUP = "template-limits"
SERVICES = ["cloudformation"]

_LIMIT = 51200
_TAGS = [{"Key": "sim2real-check", "Value": CHECK}]
_DEADLINE_S = 240.0


def _body(size: int, marker: str) -> str:
    """A valid JSON template of exactly ``size`` ASCII bytes, padded through a Metadata string."""
    skeleton = {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Metadata": {"Marker": marker, "Pad": ""},
        "Resources": {"Handle": {"Type": "AWS::CloudFormation::WaitConditionHandle"}},
    }
    skeleton["Metadata"]["Pad"] = "p" * (size - len(json.dumps(skeleton, separators=(",", ":"))))
    body = json.dumps(skeleton, separators=(",", ":"))
    assert len(body.encode("utf-8")) == size, f"built a {len(body)}-byte body, wanted {size}"
    return body


def _error(fn):
    """(code, message) of the ClientError ``fn`` raises; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err["Message"]
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _settle(cf, stack_id: str) -> dict:
    """Poll DescribeStacks by StackId until the stack leaves *_IN_PROGRESS; return the stack."""
    deadline = time.monotonic() + _DEADLINE_S
    while True:
        stack = cf.describe_stacks(StackName=stack_id)["Stacks"][0]
        if not stack["StackStatus"].endswith("_IN_PROGRESS"):
            return stack
        if time.monotonic() > deadline:
            raise AssertionError(f"{stack_id} still {stack['StackStatus']!r} after {_DEADLINE_S}s")
        time.sleep(3.0)


def _delete_stack(cf, stack_id: str) -> None:
    """DeleteStack, then poll by StackId to DELETE_COMPLETE; DELETE_FAILED or a timeout raises."""
    cf.delete_stack(StackName=stack_id)
    # The first read after DeleteStack may still show the prior status, so only the two terminal
    # delete states end the poll.
    deadline = time.monotonic() + _DEADLINE_S
    while True:
        stack = cf.describe_stacks(StackName=stack_id)["Stacks"][0]
        if stack["StackStatus"] == "DELETE_COMPLETE":
            return
        if stack["StackStatus"] == "DELETE_FAILED" or time.monotonic() > deadline:
            raise AssertionError(
                f"stack {stack_id} ended {stack['StackStatus']!r}: {stack.get('StackStatusReason')!r}"
            )
        time.sleep(3.0)


def _refused_create(ctx, cf, name: str, body: str):
    """(code, message) of a CreateStack that must be refused; a stack it wrongly made is deleted."""
    try:
        stack_id = cf.create_stack(StackName=name, TemplateBody=body, Tags=_TAGS)["StackId"]
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err["Message"]
    ctx.on_cleanup(lambda: _delete_stack(cf, stack_id))
    raise AssertionError(f"CreateStack {name} was accepted as {stack_id}; it must be refused")


def _length_message(body: str) -> str:
    """The exact ValidationError message: the value is echoed only through its first 100 bytes."""
    return (
        f"1 validation error detected: Value '{body[:100]}...<{len(body)} chars total>' at "
        f"'templateBody' failed to satisfy constraint: Member must have length less than or "
        f"equal to {_LIMIT}"
    )


@tags("axis:rejection", "cap:c3", "concern:deploy", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A 51,200-byte TemplateBody deploys and is stored whole; one byte more is refused by
    CreateStack (no stack), UpdateStack and CreateChangeSet, leaving the deployed stack unchanged.

    Reference: https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/cloudformation-limits.html
    """
    cf = ctx.client("cloudformation")

    at_limit = _body(_LIMIT, "v1")
    name = ctx.unique_name("sim2real-behav-tplsize-")
    stack_id = cf.create_stack(StackName=name, TemplateBody=at_limit, Tags=_TAGS)["StackId"]
    ctx.on_cleanup(lambda: _delete_stack(cf, stack_id))
    created = _settle(cf, stack_id)
    assert created["StackStatus"] == "CREATE_COMPLETE", (
        f"a {_LIMIT}-byte template must deploy; got {created['StackStatus']!r}: "
        f"{created.get('StackStatusReason')!r}"
    )
    stored = cf.get_template(StackName=stack_id)["TemplateBody"]
    assert stored == json.loads(at_limit), "GetTemplate must return the whole 51,200-byte template"

    over_new = _body(_LIMIT + 1, "v1")
    refused = ctx.unique_name("sim2real-behav-tplsize-over-")
    code, msg = _refused_create(ctx, cf, refused, over_new)
    assert (code, msg) == ("ValidationError", _length_message(over_new)), (
        f"CreateStack of {_LIMIT + 1} bytes: got {code!r} {msg[:160]!r}...{msg[-120:]!r}"
    )
    gone = _error(lambda: cf.describe_stacks(StackName=refused))
    assert gone == ("ValidationError", f"Stack with id {refused} does not exist"), (
        f"a refused create must leave no stack; DescribeStacks gave {gone!r}"
    )

    over_update = _body(_LIMIT + 1, "v2")
    code, msg = _error(lambda: cf.update_stack(StackName=stack_id, TemplateBody=over_update))
    assert (code, msg) == ("ValidationError", _length_message(over_update)), (
        f"UpdateStack of {_LIMIT + 1} bytes: got {code!r} {msg[:160]!r}...{msg[-120:]!r}"
    )
    change_set = ctx.unique_name("sim2real-cs-")
    code, msg = _error(lambda: cf.create_change_set(
        StackName=stack_id, ChangeSetName=change_set, TemplateBody=over_update,
    ))
    assert (code, msg) == ("ValidationError", _length_message(over_update)), (
        f"CreateChangeSet of {_LIMIT + 1} bytes: got {code!r} {msg[:160]!r}...{msg[-120:]!r}"
    )

    after = cf.describe_stacks(StackName=stack_id)["Stacks"][0]
    assert after["StackStatus"] == "CREATE_COMPLETE", f"stack status became {after['StackStatus']!r}"
    assert after.get("LastUpdatedTime") == created.get("LastUpdatedTime"), (
        f"a refused update moved LastUpdatedTime to {after.get('LastUpdatedTime')!r}"
    )
    sets = cf.list_change_sets(StackName=stack_id)["Summaries"]
    assert sets == [], f"a refused CreateChangeSet left change sets {sets!r}"
    marker = cf.get_template(StackName=stack_id)["TemplateBody"]["Metadata"]["Marker"]
    assert marker == "v1", f"the stored template changed to marker {marker!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
