"""get-role-returns-tags-list-roles-omits-them."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "get-role-returns-tags-list-roles-omits-them"
GROUP = "tags"
SERVICES = ["iam"]

_TRUST_DOC = json.dumps(
    {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
)


def _list_all(paginate_fn, key, **kwargs):
    out = []
    for page in paginate_fn(**kwargs):
        out.extend(page[key])
    return out


@tags("axis:happy-path", "cap:c1", "concern:representation", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetRole returns a role's Tags and Description as created, while ListRoles lists the same
    role without Tags; IaC drift checks rely on this split."""
    iam = ctx.client("iam")
    suffix = ctx.unique_name("sim2real-behav-getrole")
    role_path = f"/{suffix}/"
    role_name = f"{suffix}-role"
    tag_value = ctx.unique_name("env-")
    description = f"sim2real description {suffix}"

    created = iam.create_role(
        RoleName=role_name,
        Path=role_path,
        AssumeRolePolicyDocument=_TRUST_DOC,
        Description=description,
        Tags=[{"Key": "Environment", "Value": tag_value}],
    )["Role"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    got = iam.get_role(RoleName=role_name)["Role"]
    got_tags = {t["Key"]: t["Value"] for t in got.get("Tags", [])}
    assert got_tags.get("Environment") == tag_value, (
        f"expected GetRole to echo tag Environment={tag_value!r}, got Tags={got.get('Tags')!r}"
    )
    assert got.get("Description") == description, (
        f"expected GetRole Description {description!r}, got {got.get('Description')!r}"
    )

    listed = _list_all(iam.get_paginator("list_roles").paginate, "Roles", PathPrefix=role_path)
    assert len(listed) == 1, f"expected exactly 1 role under {role_path!r}, got {listed!r}"
    summary = listed[0]
    assert summary["Arn"] == created["Arn"], f"listed Arn {summary['Arn']!r} != created Arn {created['Arn']!r}"
    assert "Tags" not in summary or not summary["Tags"], (
        f"expected ListRoles to omit Tags for a tagged role, got {summary.get('Tags')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
