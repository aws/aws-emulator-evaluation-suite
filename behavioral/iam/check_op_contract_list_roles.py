"""op-contract-list-roles."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-list-roles"
GROUP = "error-semantics"
SERVICES = ["iam"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListRoles(PathPrefix=...) scopes results to a freshly created role's unique path;
    malformed PathPrefix -> ValidationError."""
    iam = ctx.client("iam")

    role_path = f"/{ctx.unique_name('sim2real-behav-path-')}/"
    role_name = ctx.unique_name("sim2real-behav-role-")
    created = iam.create_role(
        RoleName=role_name, Path=role_path, AssumeRolePolicyDocument=_trust_doc()
    )["Role"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    roles = _list_all(iam.list_roles, "Roles", PathPrefix=role_path)
    assert len(roles) == 1, f"expected exactly 1 role under {role_path}, got {roles}"
    assert roles[0]["RoleName"] == role_name, (
        f"expected RoleName {role_name!r}, got {roles[0]['RoleName']!r}"
    )
    assert roles[0]["Path"] == role_path, f"expected Path {role_path!r}, got {roles[0]['Path']!r}"
    assert roles[0]["Arn"] == created["Arn"], (
        f"expected Arn {created['Arn']!r}, got {roles[0]['Arn']!r}"
    )

    code, message = _error(lambda: iam.list_roles(PathPrefix="badpath"))
    assert code == "ValidationError", f"expected ValidationError, got {code}"
    expected = (
        "The specified value for pathPrefix is invalid. It must begin with the / character "
        "and contain only alphanumeric characters and/or / characters."
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"


def _trust_doc() -> str:
    return json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Service": "ec2.amazonaws.com"},
                    "Action": "sts:AssumeRole",
                }
            ],
        }
    )


def _list_all(fn, list_key, **kwargs):
    items = []
    marker = None
    while True:
        params = dict(kwargs)
        if marker:
            params["Marker"] = marker
        resp = fn(**params)
        items.extend(resp.get(list_key, []))
        if not resp.get("IsTruncated"):
            break
        marker = resp.get("Marker")
    return items


def _error(fn) -> tuple[str, str]:
    """Call fn(); return its error (Code, Message). An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
