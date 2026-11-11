"""list-roles-by-path-prefix."""
from __future__ import annotations

import json

from behavioral_harness import tags

MINIMAL_TRUST_POLICY = json.dumps(
    {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "lambda.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
)

CHECK = "list-roles-by-path-prefix"
GROUP = 'path_handling'
SERVICES = ['iam']

@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListRoles with PathPrefix filters to roles under that path."""
    iam = ctx.client("iam")
    path = f"/sim2real/{ctx.unique_name('pathtest-')}/"
    tags = [{"Key": "sim2real", "Value": CHECK}]
    name1 = ctx.unique_name("sim2real-behav-role-")
    iam.create_role(RoleName=name1, AssumeRolePolicyDocument=MINIMAL_TRUST_POLICY, Path=path, Tags=tags)
    ctx.on_cleanup(lambda n=name1: iam.delete_role(RoleName=n))
    name2 = ctx.unique_name("sim2real-behav-role-")
    iam.create_role(RoleName=name2, AssumeRolePolicyDocument=MINIMAL_TRUST_POLICY, Path="/", Tags=tags)
    ctx.on_cleanup(lambda n=name2: iam.delete_role(RoleName=n))
    pages = iam.get_paginator("list_roles").paginate(PathPrefix=path)
    role_names = [r["RoleName"] for page in pages for r in page["Roles"]]
    assert name1 in role_names, f"expected {name1} under {path} in {role_names}"
    assert name2 not in role_names, f"expected {name2} (Path=/) excluded by PathPrefix={path}, got {role_names}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
