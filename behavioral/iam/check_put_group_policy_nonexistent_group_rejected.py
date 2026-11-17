"""put-group-policy-nonexistent-group-rejected."""
from __future__ import annotations

import json
from typing import Any

from behavioral_harness import tags

CHECK = "put-group-policy-nonexistent-group-rejected"
GROUP = "overly-permissive"
SERVICES = ["iam"]

_POLICY_DOC = json.dumps(
    {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "s3:ListBucket", "Resource": "*"}]}
)


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutGroupPolicy rejects a GroupName that names no group with NoSuchEntity, creating no
    policy; the identical call against a real, existing group succeeds."""
    iam = ctx.client("iam")
    bogus_group = ctx.unique_name("sim2real-grp-never-created-")

    code, message = _error(
        lambda: iam.put_group_policy(GroupName=bogus_group, PolicyName="probe", PolicyDocument=_POLICY_DOC)
    )
    assert code == "NoSuchEntity", f"expected NoSuchEntity, got {code}"
    expected = f"The group with name {bogus_group} cannot be found."
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Effect absent: no group was fabricated by the rejected PutGroupPolicy.
    group_code, group_message = _error(lambda: iam.get_group(GroupName=bogus_group))
    assert group_code == "NoSuchEntity", (
        f"a rejected PutGroupPolicy must not have created the group, got {group_code}"
    )
    expected_group_message = f"The group with name {bogus_group} cannot be found."
    assert group_message == expected_group_message, (
        f"expected message {expected_group_message!r}, got {group_message!r}"
    )

    # Positive control: the identical call against a real, existing group succeeds.
    real_group = ctx.unique_name("sim2real-grp-real-")
    iam.create_group(GroupName=real_group)
    ctx.on_cleanup(lambda: iam.delete_group(GroupName=real_group))
    iam.put_group_policy(GroupName=real_group, PolicyName="probe", PolicyDocument=_POLICY_DOC)
    ctx.on_cleanup(lambda: iam.delete_group_policy(GroupName=real_group, PolicyName="probe"))
    names = iam.list_group_policies(GroupName=real_group)["PolicyNames"]
    assert names == ["probe"], f"expected the inline policy to be stored, got {names!r}"


def _error(fn: Any) -> tuple[str, str]:
    """Call fn(); return the (code, message) of the ClientError it raises. An unexpected SUCCESS
    raises, because an emulator ACCEPTING input real AWS refuses is the strongest signal available."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(
        f"real AWS rejects PutGroupPolicy on a group that was never created, but it SUCCEEDED "
        f"and returned {result!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
