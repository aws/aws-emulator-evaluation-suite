"""create-packaging-group-missing-permission-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-packaging-group-missing-permission-rejected"
GROUP = "overly-permissive"
SERVICES = ["mediapackage-vod"]


@tags("axis:rejection", "cap:c7", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A principal with no mediapackage-vod permissions attached is rejected with
    AccessDeniedException on CreatePackagingGroup, no group is created under that request, and the
    caller's own (permitted) credentials still succeed (positive control)."""
    iam = ctx.client("iam")

    account_id = ctx.account
    role_name = ctx.unique_name("sim2real-mpvod-nopermrole-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"}, "Action": "sts:AssumeRole"}
        ],
    }
    role = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust_policy))
    role_arn = role["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    denied_group_id = ctx.unique_name("sim2real-mpvod-deniedgroup-")
    code, message = _try_create_group_as_unprivileged_role(
        ctx, role_arn, denied_group_id, timeout_s=60.0
    )
    assert code == "AccessDeniedException", (
        f"a principal with no mediapackage-vod permissions must be refused CreatePackagingGroup "
        f"with AccessDeniedException; got {code!r}"
    )
    expected_denial = (
        f"User: arn:aws:sts::{account_id}:assumed-role/{role_name}/{_SESSION_NAME} is not "
        f"authorized to perform: mediapackage-vod:CreatePackagingGroup on resource: "
        f"arn:aws:mediapackage-vod:{ctx.region}:{account_id}:packaging-groups/* because no "
        f"identity-based policy allows the mediapackage-vod:CreatePackagingGroup action"
    )
    assert message == expected_denial, (
        f"expected denial message {expected_denial!r}, got {message!r}"
    )

    # Effect absent: the group was never created.
    mpv = ctx.client("mediapackage-vod")
    denied_lookup, denied_message = _error(lambda: mpv.describe_packaging_group(Id=denied_group_id))
    assert denied_lookup == "NotFoundException", (
        f"the denied CreatePackagingGroup must have no effect, so an independent "
        f"DescribePackagingGroup on {denied_group_id!r} must report NotFoundException; got "
        f"{denied_lookup!r}"
    )
    expected_absent = f"PackagingGroup with id={denied_group_id} not found"
    assert denied_message == expected_absent, (
        f"expected message {expected_absent!r}, got {denied_message!r}"
    )

    # Positive control: the test's own (permitted) credentials can create a packaging group, and
    # the terminal assertion is an independent read at the destination, not the create response.
    control_group_id = ctx.unique_name("sim2real-mpvod-controlgroup-")
    created = mpv.create_packaging_group(Id=control_group_id)
    ctx.on_cleanup(lambda: mpv.delete_packaging_group(Id=control_group_id))
    assert created["Id"] == control_group_id, (
        f"CreatePackagingGroup response Id mismatch: expected {control_group_id!r}, got "
        f"{created['Id']!r}"
    )
    described = mpv.describe_packaging_group(Id=control_group_id)
    assert described["Id"] == control_group_id, (
        f"an independent DescribePackagingGroup for the control group must find it by "
        f"{control_group_id!r}; got {described.get('Id')!r}"
    )


_SESSION_NAME = "sim2real-mpvod-no-perm-check"


def _error(fn):
    """The (code, message) of the ClientError ``fn`` raises; a call that succeeds fails the check."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")


def _try_create_group_as_unprivileged_role(ctx, role_arn: str, group_id: str, timeout_s: float = 60.0):
    """Assume the freshly-created role (retrying past IAM trust-policy propagation lag) and attempt
    CreatePackagingGroup with its (permission-less) credentials; returns the error code and message."""
    sts = ctx.client("sts")
    deadline = time.monotonic() + timeout_s
    creds = None
    while time.monotonic() < deadline:
        try:
            creds = sts.assume_role(
                RoleArn=role_arn, RoleSessionName=_SESSION_NAME
            )["Credentials"]
            break
        except ClientError as e:
            if e.response["Error"]["Code"] in ("AccessDenied", "AccessDeniedException"):
                time.sleep(3.0)
                continue
            raise
    if creds is None:
        raise AssertionError("could not assume the freshly created role within the timeout")

    unprivileged = ctx.client(
        "mediapackage-vod",
        creds={
            "aws_access_key_id": creds["AccessKeyId"],
            "aws_secret_access_key": creds["SecretAccessKey"],
            "aws_session_token": creds["SessionToken"],
        },
    )
    return _error(lambda: unprivileged.create_packaging_group(Id=group_id))



if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
