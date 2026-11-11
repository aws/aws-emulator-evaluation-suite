"""op-contract-deleteGroupPolicy."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "op-contract-deleteGroupPolicy"
GROUP = "error-semantics"
SERVICES = ["iam"]


def _error(fn):
    """Call fn(); return its (code, message). An unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeleteGroupPolicy removes only the named inline policy; reading or re-deleting it, and
    deleting a never-created name, fail NoSuchEntity with AWS's exact message."""
    iam = ctx.client("iam")
    group = ctx.unique_name("sim2real-behav-gpgroup-")
    iam.create_group(GroupName=group)
    ctx.on_cleanup(lambda: iam.delete_group(GroupName=group))

    doc = json.dumps({"Version": "2012-10-17", "Statement": [{"Effect": "Deny", "Action": "*", "Resource": "*"}]})
    iam.put_group_policy(GroupName=group, PolicyName="keep-me", PolicyDocument=doc)
    ctx.on_cleanup(lambda: iam.delete_group_policy(GroupName=group, PolicyName="keep-me"))
    iam.put_group_policy(GroupName=group, PolicyName="remove-me", PolicyDocument=doc)

    iam.delete_group_policy(GroupName=group, PolicyName="remove-me")
    names = iam.list_group_policies(GroupName=group)["PolicyNames"]
    assert names == ["keep-me"], f"expected only the sibling policy to survive, got {names!r}"

    code, message = _error(lambda: iam.get_group_policy(GroupName=group, PolicyName="remove-me"))
    assert code == "NoSuchEntity", code
    expected = "The group policy with name remove-me cannot be found."
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    code_redelete, message_redelete = _error(
        lambda: iam.delete_group_policy(GroupName=group, PolicyName="remove-me")
    )
    assert code_redelete == "NoSuchEntity", code_redelete
    assert message_redelete == expected, f"expected message {expected!r}, got {message_redelete!r}"

    code2, message2 = _error(lambda: iam.delete_group_policy(GroupName=group, PolicyName="never-existed"))
    assert code2 == "NoSuchEntity", code2
    expected2 = "The group policy with name never-existed cannot be found."
    assert message2 == expected2, f"expected message {expected2!r}, got {message2!r}"
    names_final = iam.list_group_policies(GroupName=group)["PolicyNames"]
    assert names_final == ["keep-me"], f"expected the sibling policy untouched by the rejected deletes, got {names_final!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
