"""duplicate-stackset-name-rejected."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "duplicate-stackset-name-rejected"
GROUP = "overly-permissive"
SERVICES = ["cloudformation"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateStackSet with a StackSetName that already exists in the account
    and Region must fail with NameAlreadyExistsException rather than
    overwriting the existing StackSet's definition."""
    cfn = ctx.client("cloudformation")
    stackset_name = ctx.unique_name("sim2real-behav-dupss-")
    template_v1 = json.dumps({"Resources": {"Topic": {"Type": "AWS::SNS::Topic", "Properties": {}}}})
    template_v2 = json.dumps({
        "Resources": {
            "Topic": {"Type": "AWS::SNS::Topic", "Properties": {}},
            "Topic2": {"Type": "AWS::SNS::Topic", "Properties": {}},
        },
    })

    cfn.create_stack_set(StackSetName=stackset_name, TemplateBody=template_v1)
    ctx.on_cleanup(lambda: cfn.delete_stack_set(StackSetName=stackset_name))

    err = _expect_error(
        lambda: cfn.create_stack_set(StackSetName=stackset_name, TemplateBody=template_v2)
    ).response["Error"]
    assert err["Code"] == "NameAlreadyExistsException", (
        f"expected NameAlreadyExistsException, got {err['Code']!r}"
    )
    assert err.get("Message") == "StackSet already exists.", (
        f"expected message 'StackSet already exists.', got {err.get('Message')!r}"
    )

    # The original definition must be untouched by the rejected duplicate call.
    current_template = json.loads(cfn.describe_stack_set(StackSetName=stackset_name)["StackSet"]["TemplateBody"])
    assert list(current_template["Resources"].keys()) == ["Topic"], (
        f"stack set template appears to have been overwritten by the rejected duplicate: {current_template}"
    )

    # Restore: the block is the name being in use, not the name itself, so removing the
    # original must free it for the identical call that was rejected a moment ago.
    cfn.delete_stack_set(StackSetName=stackset_name)
    cfn.create_stack_set(StackSetName=stackset_name, TemplateBody=template_v2)
    restored_template = json.loads(cfn.describe_stack_set(StackSetName=stackset_name)["StackSet"]["TemplateBody"])
    assert list(restored_template["Resources"].keys()) == ["Topic", "Topic2"], (
        f"identical call should have succeeded once the name was freed, got template {restored_template}"
    )


def _expect_error(fn):
    """Call fn(); return the raised ClientError. Raise if fn() succeeds unexpectedly."""
    try:
        result = fn()
    except ClientError as exc:
        return exc
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
