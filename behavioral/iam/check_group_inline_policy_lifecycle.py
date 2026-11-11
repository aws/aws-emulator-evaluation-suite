"""group-inline-policy-lifecycle."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "group-inline-policy-lifecycle"
GROUP = "state-machine"
SERVICES = ["iam"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Group inline policy put->visible-in-get/list->deleted->absent transitions."""
    iam = ctx.client("iam")
    group_name = ctx.unique_name("sim2real-behav-inlinegroup-")
    policy_name = ctx.unique_name("sim2real-behav-inlinepolicy-")

    iam.create_group(GroupName=group_name)
    ctx.on_cleanup(lambda: iam.delete_group(GroupName=group_name))

    policy_doc = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "s3:ListAllMyBuckets", "Resource": "*"}],
    }
    iam.put_group_policy(
        GroupName=group_name, PolicyName=policy_name, PolicyDocument=json.dumps(policy_doc)
    )
    ctx.on_cleanup(
        lambda: _ignore_no_such_entity(
            lambda: iam.delete_group_policy(GroupName=group_name, PolicyName=policy_name)
        )
    )

    got = iam.get_group_policy(GroupName=group_name, PolicyName=policy_name)
    assert got["PolicyDocument"]["Statement"][0]["Action"] == "s3:ListAllMyBuckets", (
        f"expected the put document's Action to round-trip through GetGroupPolicy, got {got['PolicyDocument']!r}"
    )

    names = iam.list_group_policies(GroupName=group_name)["PolicyNames"]
    assert policy_name in names, f"expected {policy_name!r} in ListGroupPolicies {names!r} after PutGroupPolicy"

    iam.delete_group_policy(GroupName=group_name, PolicyName=policy_name)

    names_after = iam.list_group_policies(GroupName=group_name)["PolicyNames"]
    assert policy_name not in names_after, (
        f"expected {policy_name!r} gone from ListGroupPolicies {names_after!r} after DeleteGroupPolicy"
    )
    mutate_code, mutate_message = _error(
        lambda: iam.delete_group_policy(GroupName=group_name, PolicyName=policy_name)
    )
    assert mutate_code == "NoSuchEntity", (
        f"DeleteGroupPolicy on the already-deleted policy: expected NoSuchEntity, got "
        f"{mutate_code!r}: {mutate_message!r}"
    )
    expected = f"The group policy with name {policy_name} cannot be found."
    assert mutate_message == expected, (
        f"DeleteGroupPolicy NoSuchEntity message: expected {expected!r}, got {mutate_message!r}"
    )

    read_code, read_message = _error(
        lambda: iam.get_group_policy(GroupName=group_name, PolicyName=policy_name)
    )
    assert read_code == "NoSuchEntity", (
        f"GetGroupPolicy on the deleted policy: expected NoSuchEntity, got {read_code!r}: {read_message!r}"
    )
    expected = f"The group policy with name {policy_name} cannot be found."
    assert read_message == expected, (
        f"GetGroupPolicy NoSuchEntity message: expected {expected!r}, got {read_message!r}"
    )


def _error(fn):
    """(code, message) of the ClientError fn() raises; an unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError but the call succeeded with {result!r}")


def _ignore_no_such_entity(fn):
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
