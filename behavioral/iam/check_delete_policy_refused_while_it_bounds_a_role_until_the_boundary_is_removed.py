"""delete-policy-refused-while-it-bounds-a-role-until-the-boundary-is-removed."""

from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-policy-refused-while-it-bounds-a-role-until-the-boundary-is-removed"
GROUP = "errors"
SERVICES = ["iam"]

ERR_DELETE_CONFLICT = "DeleteConflict"
ERR_NO_SUCH_ENTITY = "NoSuchEntity"

TRUST_POLICY = json.dumps(
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

BOUNDARY_DOCUMENT = json.dumps(
    {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": ["logs:*", "s3:GetObject"], "Resource": "*"}],
    }
)


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A managed policy set as a role's permissions boundary counts as a boundary use, not an
    attachment, yet DeletePolicy is refused with DeleteConflict while it bounds the role; after
    DeleteRolePermissionsBoundary the identical DeletePolicy succeeds and the role survives."""
    iam = ctx.client("iam")
    path = f"/bounded/{ctx.unique_name('p-')}/"
    policy_name = ctx.unique_name("sim2real-behav-boundary-")
    arn = iam.create_policy(
        PolicyName=policy_name,
        PolicyDocument=BOUNDARY_DOCUMENT,
        Path=path,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Policy"]["Arn"]
    ctx.on_cleanup(lambda a=arn: _quiet(lambda: iam.delete_policy(PolicyArn=a)))
    role = ctx.unique_name("sim2real-behav-bounded-role-")
    iam.create_role(
        RoleName=role,
        AssumeRolePolicyDocument=TRUST_POLICY,
        Path=path,
        PermissionsBoundary=arn,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda n=role: _quiet(lambda: iam.delete_role(RoleName=n)))
    ctx.on_cleanup(lambda n=role: _quiet(lambda: iam.delete_role_permissions_boundary(RoleName=n)))

    boundary = iam.get_role(RoleName=role)["Role"].get("PermissionsBoundary")
    expected_boundary = {"PermissionsBoundaryType": "Policy", "PermissionsBoundaryArn": arn}
    assert boundary == expected_boundary, (
        f"GetRole PermissionsBoundary {boundary!r}, expected {expected_boundary!r}"
    )
    policy = iam.get_policy(PolicyArn=arn)["Policy"]
    counts = (policy["AttachmentCount"], policy["PermissionsBoundaryUsageCount"])
    assert counts == (0, 1), (
        f"GetPolicy (AttachmentCount, PermissionsBoundaryUsageCount) {counts!r}, expected (0, 1)"
    )
    attached = iam.list_attached_role_policies(RoleName=role)["AttachedPolicies"]
    assert attached == [], (
        f"a boundary is not an attachment, but ListAttachedRolePolicies lists {attached!r}"
    )

    refusal = _error(lambda: iam.delete_policy(PolicyArn=arn))
    _assert_error(refusal, ERR_DELETE_CONFLICT, 409)
    conflict = "Cannot delete a policy attached to entities."
    assert refusal["Error"].get("Message") == conflict, (
        f"expected {conflict!r}, got {refusal['Error']!r}"
    )
    # Effect absent: the policy and the boundary both survive the rejected delete.
    assert iam.get_policy(PolicyArn=arn)["Policy"]["Arn"] == arn, (
        "the policy did not survive a rejected delete"
    )
    boundary = iam.get_role(RoleName=role)["Role"].get("PermissionsBoundary")
    assert boundary == expected_boundary, (
        f"after the rejected delete PermissionsBoundary is {boundary!r}"
    )

    # Restore: remove the boundary, then reissue the identical call.
    iam.delete_role_permissions_boundary(RoleName=role)
    role_after = iam.get_role(RoleName=role)["Role"]
    assert "PermissionsBoundary" not in role_after, (
        f"GetRole still reports {role_after.get('PermissionsBoundary')!r}"
    )
    usage = iam.get_policy(PolicyArn=arn)["Policy"]["PermissionsBoundaryUsageCount"]
    assert usage == 0, (
        f"PermissionsBoundaryUsageCount after the boundary is removed {usage!r}, expected 0"
    )
    iam.delete_policy(PolicyArn=arn)
    gone = f"Policy {arn} was not found."
    refusal = _error(lambda: iam.get_policy(PolicyArn=arn))
    _assert_error(refusal, ERR_NO_SUCH_ENTITY, 404)
    assert refusal["Error"].get("Message") == gone, (
        f"GetPolicy: expected {gone!r}, got {refusal['Error']!r}"
    )
    assert iam.get_role(RoleName=role)["Role"]["RoleName"] == role, (
        "the role did not survive its boundary's deletion"
    )


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
