"""create-role-with-tags."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

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

CHECK = "create-role-with-tags"
GROUP = 'tags'
SERVICES = ['iam']

@tags("axis:happy-path", "cap:c1", "concern:representation", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateRole with Tags parameter; tags are immediately visible via an independent
    ListRoleTags read, and the same read returns NoSuchEntity once the role is deleted."""
    iam = ctx.client("iam")
    tag_set = [{"Key": "created-with", "Value": "tags"}]
    role = ctx.unique_name("sim2real-behav-role-")
    iam.create_role(RoleName=role, AssumeRolePolicyDocument=MINIMAL_TRUST_POLICY, Path="/", Tags=tag_set)
    ctx.on_cleanup(lambda n=role: _ignore_no_such_entity(lambda: iam.delete_role(RoleName=n)))

    resp = iam.list_role_tags(RoleName=role)
    tag_map = {t["Key"]: t["Value"] for t in resp["Tags"]}
    assert tag_map == {"created-with": "tags"}, f"expected exactly the tags set at creation, got {tag_map}"

    iam.delete_role(RoleName=role)
    code, message = _error(lambda: iam.list_role_tags(RoleName=role))
    assert code == "NoSuchEntity", f"expected NoSuchEntity after delete, got {code}"
    assert message == f"The role with name {role} cannot be found.", (
        f"ListRoleTags on the deleted role message: {message!r}"
    )


def _ignore_no_such_entity(fn):
    """Teardown-only: tolerate the role already being gone."""
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _error(fn):
    """Call fn(); return (Error.Code, Error.Message) of the ClientError it must raise."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to fail, but it succeeded with {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
