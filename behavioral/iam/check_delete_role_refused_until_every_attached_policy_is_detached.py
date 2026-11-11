"""delete-role-refused-until-every-attached-policy-is-detached."""

from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-role-refused-until-every-attached-policy-is-detached"
GROUP = "errors"
SERVICES = ["iam"]

ERR_DELETE_CONFLICT = "DeleteConflict"
ERR_NO_SUCH_ENTITY = "NoSuchEntity"
CONFLICT = "Cannot delete entity, must detach all policies first."

TRUST_POLICY = json.dumps(
    {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": ["ecs-tasks.amazonaws.com", "states.amazonaws.com"]},
                "Action": "sts:AssumeRole",
            }
        ],
    }
)


def _policy(action: str) -> str:
    return json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": action, "Resource": "*"}],
        }
    )


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A role with three attached managed policies refuses DeleteRole with DeleteConflict while any
    one stays attached: each refusal leaves exactly the remaining attachments, and only after the
    last detach does the identical DeleteRole succeed and the role read as gone."""
    iam = ctx.client("iam")
    role = ctx.unique_name("sim2real-behav-role3-")
    path = f"/deep/{ctx.unique_name('a-')}/{ctx.unique_name('b-')}/"
    iam.create_role(
        RoleName=role,
        AssumeRolePolicyDocument=TRUST_POLICY,
        Path=path,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda n=role: _quiet(lambda: iam.delete_role(RoleName=n)))
    arns = []
    for action in ("sqs:GetQueueUrl", "sns:ListTopics", "logs:DescribeLogGroups"):
        arn = iam.create_policy(
            PolicyName=ctx.unique_name("sim2real-behav-pol-"),
            PolicyDocument=_policy(action),
            Path=path,
            Tags=[{"Key": "sim2real", "Value": CHECK}],
        )["Policy"]["Arn"]
        ctx.on_cleanup(lambda a=arn: iam.delete_policy(PolicyArn=a))
        iam.attach_role_policy(RoleName=role, PolicyArn=arn)
        ctx.on_cleanup(
            lambda r=role, p=arn: _quiet(lambda: iam.detach_role_policy(RoleName=r, PolicyArn=p))
        )
        arns.append(arn)

    # Detach in reverse attach order; every refusal before the last detach is the same conflict.
    for still_attached in (arns, arns[:2], arns[:1]):
        if still_attached is not arns:
            iam.detach_role_policy(RoleName=role, PolicyArn=arns[len(still_attached)])
        refusal = _error(lambda: iam.delete_role(RoleName=role))
        _assert_error(refusal, ERR_DELETE_CONFLICT, 409)
        assert refusal["Error"].get("Message") == CONFLICT, (
            f"with {len(still_attached)} attached: expected {CONFLICT!r}, got {refusal['Error']!r}"
        )
        assert iam.get_role(RoleName=role)["Role"]["RoleName"] == role, (
            "the role did not survive a rejected delete"
        )
        attached = sorted(
            p["PolicyArn"]
            for p in iam.list_attached_role_policies(RoleName=role)["AttachedPolicies"]
        )
        assert attached == sorted(still_attached), (
            f"after a rejected delete {len(attached)} policies are attached, expected {len(still_attached)}"
        )

    iam.detach_role_policy(RoleName=role, PolicyArn=arns[0])
    iam.delete_role(RoleName=role)
    gone = f"The role with name {role} cannot be found."
    refusal = _error(lambda: iam.get_role(RoleName=role))
    _assert_error(refusal, ERR_NO_SUCH_ENTITY, 404)
    assert refusal["Error"].get("Message") == gone, (
        f"GetRole: expected {gone!r}, got {refusal['Error']!r}"
    )
    refusal = _error(lambda: iam.attach_role_policy(RoleName=role, PolicyArn=arns[0]))
    _assert_error(refusal, ERR_NO_SUCH_ENTITY, 404)
    assert refusal["Error"].get("Message") == gone, (
        f"AttachRolePolicy: expected {gone!r}, got {refusal['Error']!r}"
    )
    # The policies outlive the role, each with no attachment left.
    counts = [iam.get_policy(PolicyArn=a)["Policy"]["AttachmentCount"] for a in arns]
    assert counts == [0, 0, 0], (
        f"policy AttachmentCounts after the role is gone {counts!r}, expected [0, 0, 0]"
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
