"""put-group-policy-overwrite-replaces-the-prior-document."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "put-group-policy-overwrite-replaces-the-prior-document"
GROUP = "inline-policies"
SERVICES = ["iam"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A second PutGroupPolicy under the same PolicyName replaces the stored document whole;
    GetGroupPolicy reflects only the new statement, never a merge of the two.
    """
    iam = ctx.client("iam")
    group_name = ctx.unique_name("sim2real-behav-pgp-group-")
    policy_name = "sim2real-behav-pgp-inline"

    iam.create_group(GroupName=group_name)
    ctx.on_cleanup(lambda: iam.delete_group(GroupName=group_name))

    doc_v1 = {
        "Version": "2012-10-17",
        "Statement": [{"Sid": "First", "Effect": "Allow", "Action": "s3:ListBucket", "Resource": "*"}],
    }
    iam.put_group_policy(GroupName=group_name, PolicyName=policy_name, PolicyDocument=json.dumps(doc_v1))
    ctx.on_cleanup(lambda: iam.delete_group_policy(GroupName=group_name, PolicyName=policy_name))

    got_v1 = iam.get_group_policy(GroupName=group_name, PolicyName=policy_name)["PolicyDocument"]
    sids_v1 = {s["Sid"] for s in got_v1["Statement"]}
    assert sids_v1 == {"First"}, f"expected only the first statement, got {sids_v1!r}"

    doc_v2 = {
        "Version": "2012-10-17",
        "Statement": [{"Sid": "Second", "Effect": "Deny", "Action": "s3:DeleteBucket", "Resource": "*"}],
    }
    iam.put_group_policy(GroupName=group_name, PolicyName=policy_name, PolicyDocument=json.dumps(doc_v2))

    got_v2 = iam.get_group_policy(GroupName=group_name, PolicyName=policy_name)["PolicyDocument"]
    sids_v2 = {s["Sid"] for s in got_v2["Statement"]}
    assert sids_v2 == {"Second"}, (
        f"PutGroupPolicy on an existing name must replace the document whole, "
        f"not merge statements; expected only 'Second', got {sids_v2!r}"
    )

    names = iam.list_group_policies(GroupName=group_name)["PolicyNames"]
    assert names == [policy_name], f"expected exactly one inline policy name, got {names!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
