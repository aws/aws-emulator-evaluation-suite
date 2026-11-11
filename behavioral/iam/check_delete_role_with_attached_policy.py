"""delete-role-with-attached-policy."""
from __future__ import annotations

from botocore.exceptions import ClientError

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

MINIMAL_POLICY_DOCUMENT = json.dumps(
    {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "iam:GetUser",
                "Resource": "arn:aws:iam::*:user/sim2real-behav-*",
            }
        ],
    }
)

CHECK = "delete-role-with-attached-policy"
GROUP = 'errors'
SERVICES = ['iam']

ERR_DELETE_CONFLICT = "DeleteConflict"
ERR_NO_SUCH_ENTITY = "NoSuchEntity"


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteRole while a managed policy is attached raises DeleteConflict, the role and the
    attachment both survive the rejected delete, and once the policy is detached the identical
    DeleteRole call succeeds and the role is gone."""
    iam = ctx.client("iam")
    role = ctx.unique_name("sim2real-behav-role-")
    path = f"/sim2real/{ctx.unique_name('p-')}/"
    iam.create_role(RoleName=role, AssumeRolePolicyDocument=MINIMAL_TRUST_POLICY, Path=path)
    ctx.on_cleanup(lambda n=role: _quiet(lambda: iam.delete_role(RoleName=n)))
    arn = iam.create_policy(PolicyName=ctx.unique_name("sim2real-behav-pol-"), PolicyDocument=MINIMAL_POLICY_DOCUMENT, Path="/")["Policy"]["Arn"]
    ctx.on_cleanup(lambda a=arn: iam.delete_policy(PolicyArn=a))
    iam.attach_role_policy(RoleName=role, PolicyArn=arn)
    ctx.on_cleanup(lambda r=role, p=arn: _quiet(lambda: iam.detach_role_policy(RoleName=r, PolicyArn=p)))

    # The refusal is graded on code + 4xx (AWS answers 409) + the exact message.
    refusal = _error(lambda: iam.delete_role(RoleName=role))
    _assert_error(refusal, ERR_DELETE_CONFLICT, 409)
    conflict = "Cannot delete entity, must detach all policies first."
    assert refusal["Error"].get("Message") == conflict, f"expected {conflict!r}, got {refusal['Error']!r}"

    # Effect absent: the rejected delete must not have touched the role or its attachment.
    still_there = iam.get_role(RoleName=role)["Role"]["RoleName"]
    assert still_there == role, f"role should survive a rejected delete, got {still_there!r}"
    attached = {
        p["PolicyArn"] for p in iam.list_attached_role_policies(RoleName=role)["AttachedPolicies"]
    }
    assert arn in attached, f"policy {arn} should still be attached after the rejected delete"

    # Restore: detach the one thing that was blocking the delete, then reissue the identical call.
    iam.detach_role_policy(RoleName=role, PolicyArn=arn)
    iam.delete_role(RoleName=role)
    # Gone: GetRole NoSuchEntity, the path lists nothing, tagging the dead role fails.
    gone = f"The role with name {role} cannot be found."
    refusal = _error(lambda: iam.get_role(RoleName=role))
    _assert_error(refusal, ERR_NO_SUCH_ENTITY, 404)
    assert refusal["Error"].get("Message") == gone, f"GetRole: expected {gone!r}, got {refusal['Error']!r}"
    listed = [r["RoleName"] for page in iam.get_paginator("list_roles").paginate(PathPrefix=path) for r in page["Roles"]]
    assert not listed, f"deleted role still listed under its path: {listed!r}"
    refusal = _error(lambda: iam.tag_role(RoleName=role, Tags=[{"Key": "after-delete", "Value": "1"}]))
    _assert_error(refusal, ERR_NO_SUCH_ENTITY, 404)
    assert refusal["Error"].get("Message") == gone, f"TagRole: expected {gone!r}, got {refusal['Error']!r}"


def _error(fn):
    """Call fn() and return its ClientError response; a call that succeeds raises AssertionError."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _assert_error(resp, code, status):
    """Grade a refusal on code + HTTP status class (AWS answers `status`) + a non-empty message."""
    err = resp.get("Error", {})
    got_status = resp.get("ResponseMetadata", {}).get("HTTPStatusCode")
    assert err.get("Code") == code, f"expected {code}, got {err.get('Code')!r}"
    assert isinstance(got_status, int) and got_status // 100 == status // 100, (
        f"expected HTTP {status // 100}xx for {code}, got {got_status!r}"
    )
    assert err.get("Message"), f"expected a non-empty {code} message, got {err!r}"


def _quiet(fn):
    """Teardown call that tolerates the resource already being gone (the body deletes it)."""
    try:
        fn()
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "NoSuchEntity":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
