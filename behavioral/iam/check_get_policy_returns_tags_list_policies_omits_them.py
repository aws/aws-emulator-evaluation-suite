"""get-policy-returns-tags-list-policies-omits-them."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "get-policy-returns-tags-list-policies-omits-them"
GROUP = "tags"
SERVICES = ["iam"]

_POLICY_DOC = json.dumps(
    {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "s3:ListBucket", "Resource": "*"}]}
)


def _list_all(paginate_fn, key, **kwargs):
    out = []
    for page in paginate_fn(**kwargs):
        out.extend(page[key])
    return out


@tags("axis:happy-path", "cap:c1", "concern:representation", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetPolicy returns a customer-managed policy's Tags and Description as created, while
    ListPolicies(Scope=Local) lists the same policy without either key."""
    iam = ctx.client("iam")
    suffix = ctx.unique_name("sim2real-behav-getpol")
    path = f"/{suffix}/"
    policy_name = f"{suffix}-policy"
    tag_value = ctx.unique_name("env-")
    description = f"sim2real description {suffix}"

    created = iam.create_policy(
        PolicyName=policy_name,
        PolicyDocument=_POLICY_DOC,
        Path=path,
        Description=description,
        Tags=[{"Key": "Environment", "Value": tag_value}],
    )["Policy"]
    arn = created["Arn"]
    ctx.on_cleanup(lambda: iam.delete_policy(PolicyArn=arn))

    got = iam.get_policy(PolicyArn=arn)["Policy"]
    got_tags = {t["Key"]: t["Value"] for t in got.get("Tags", [])}
    assert got_tags.get("Environment") == tag_value, (
        f"expected GetPolicy to echo tag Environment={tag_value!r}, got Tags={got.get('Tags')!r}"
    )
    assert got.get("Description") == description, (
        f"expected GetPolicy Description {description!r}, got {got.get('Description')!r}"
    )

    listed = _list_all(iam.get_paginator("list_policies").paginate, "Policies", Scope="Local", PathPrefix=path)
    assert len(listed) == 1, f"expected exactly 1 policy under {path!r}, got {listed!r}"
    summary = listed[0]
    assert summary["Arn"] == arn, f"listed Arn {summary['Arn']!r} != created Arn {arn!r}"
    assert "Tags" not in summary or not summary["Tags"], (
        f"expected ListPolicies to omit Tags for a tagged policy, got {summary.get('Tags')!r}"
    )
    assert "Description" not in summary or not summary["Description"], (
        f"expected ListPolicies to omit Description for a described policy, got "
        f"{summary.get('Description')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
