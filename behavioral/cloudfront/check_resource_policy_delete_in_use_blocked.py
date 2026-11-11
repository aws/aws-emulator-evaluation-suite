"""resource-policy-delete-in-use-blocked."""
from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "resource-policy-delete-in-use-blocked"
GROUP = "error-semantics"
SERVICES = ["cloudfront"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Put/Get/DeleteResourcePolicy accept only a VPC origin ARN, so each refuses a connection
    group's ARN with InvalidArgument and its exact message; the group itself reads back Enabled."""
    cf = ctx.client("cloudfront")
    group = _create_connection_group(ctx)
    policy = _build_policy(group["arn"], "cloudfront:AssociateAlias")

    # Positive control: the account and these credentials are otherwise healthy
    # for CloudFront -- the connection group we just created reads back fine and
    # enabled, so the refusals below are not "everything here is denied".
    current = cf.get_connection_group(Identifier=group["id"])
    enabled = current["ConnectionGroup"].get("Enabled", True)
    assert enabled is True, f"expected the freshly-created connection group to be Enabled, got {enabled!r}"

    # The specific refusal: PutResourcePolicy rejects a connection group ARN
    # structurally -- the resource type, not the policy's content.
    put_code, put_message = _error_code_and_message(
        lambda: cf.put_resource_policy(ResourceArn=group["arn"], PolicyDocument=json.dumps(policy))
    )
    assert put_code == "InvalidArgument", f"expected InvalidArgument, got {put_code!r}: {put_message}"
    expected_put = "The specified resource type isn't valid. Specify a VPC origin and try again."
    assert put_message == expected_put, f"expected message {expected_put!r}, got {put_message!r}"

    # Effect-absent, independently: no policy was ever attached, so a
    # GetResourcePolicy on the same ARN is refused identically -- not silently
    # treated as "not found", which would mean Put's rejection was a no-op that
    # Get doesn't agree with.
    get_code, get_message = _error_code_and_message(lambda: cf.get_resource_policy(ResourceArn=group["arn"]))
    assert get_code == "InvalidArgument", f"expected InvalidArgument, got {get_code!r}: {get_message}"
    expected_get = "The ResourceArn parameter is required. Specify a valid ARN and try again."
    assert get_message == expected_get, f"expected message {expected_get!r}, got {get_message!r}"

    # And the delete this check is named for is refused the identical way --
    # there is no "in use" state to exercise because there was never a policy
    # to delete.
    delete_code, delete_message = _error_code_and_message(
        lambda: cf.delete_resource_policy(ResourceArn=group["arn"])
    )
    assert delete_code == "InvalidArgument", f"expected InvalidArgument, got {delete_code!r}: {delete_message}"
    expected_delete = "The specified resource type isn't valid. Specify a VPC origin and try again."
    assert delete_message == expected_delete, (
        f"expected message {expected_delete!r}, got {delete_message!r}"
    )

    # Terminal, independent read: an unrelated call (DescribeConnectionGroup's
    # own resource-policy-adjacent state) still shows nothing was ever attached,
    # even after the rejected delete attempt -- the destination's own view, not
    # any of the three calls' own error response, is what settles this.
    final_get_code, final_get_message = _error_code_and_message(
        lambda: cf.get_resource_policy(ResourceArn=group["arn"])
    )
    assert final_get_code == "InvalidArgument", (
        f"expected InvalidArgument, got {final_get_code!r}: {final_get_message}"
    )
    assert final_get_message == expected_get, (
        f"expected message {expected_get!r}, got {final_get_message!r}"
    )


# ===== helpers =====


def _build_policy(resource_arn: str, action: str, principal_account: str = "111122223333") -> dict[str, Any]:
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "CrossAccountGrant",
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{principal_account}:root"},
                "Action": action,
                "Resource": resource_arn,
            }
        ],
    }


def _error_code_and_message(fn) -> tuple[str | None, str | None]:
    """Call fn(); return its botocore (code, message). An unexpected SUCCESS raises, because an
    accepted call that AWS refuses must not be reported as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response["Error"]
        return error["Code"], error.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _create_connection_group(ctx) -> dict[str, str]:
    cf = ctx.client("cloudfront")
    name = ctx.unique_name("sim2real-cg-")
    resp = cf.create_connection_group(Name=name)
    group = resp["ConnectionGroup"]
    cg_id = group["Id"]
    arn = group["Arn"]
    ctx.on_cleanup(lambda: _delete_connection_group(ctx, cg_id))
    return {"id": cg_id, "arn": arn}


def _wait_for_connection_group_status(ctx, cg_id: str, status: str, timeout_s: float = 90.0) -> dict[str, Any]:
    """Poll GetConnectionGroup until ConnectionGroup.Status == status (or timeout)."""
    cf = ctx.client("cloudfront")
    deadline = time.monotonic() + timeout_s
    last: dict[str, Any] | None = None
    while time.monotonic() < deadline:
        last = cf.get_connection_group(Identifier=cg_id)
        if last["ConnectionGroup"]["Status"] == status:
            return last
        time.sleep(3)
    if last is None:
        raise AssertionError(f"connection group {cg_id} was never readable")
    raise AssertionError(
        f"connection group {cg_id} never reached status {status!r}; "
        f"last observed status={last['ConnectionGroup']['Status']!r}"
    )


def _delete_connection_group(ctx, cg_id: str) -> None:
    cf = ctx.client("cloudfront")
    try:
        current = cf.get_connection_group(Identifier=cg_id)
    except ClientError as err:
        if err.response["Error"]["Code"] != "EntityNotFound":
            raise
        return
    group = current["ConnectionGroup"]
    etag = current["ETag"]
    if group.get("Enabled", True):
        cf.update_connection_group(Id=cg_id, IfMatch=etag, Enabled=False)
        # Disabling redeploys the group; that propagation routinely outlasts 90 s, so the
        # teardown waits up to 720 s, within the suite's cleanup budget, before it deletes.
        current = _wait_for_connection_group_status(ctx, cg_id, "Deployed", timeout_s=720.0)
        etag = current["ETag"]
    for _ in range(10):
        try:
            cf.delete_connection_group(Id=cg_id, IfMatch=etag)
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "EntityNotFound":
                return
            if code not in ("InvalidIfMatchVersion", "PreconditionFailed"):
                raise
            current = cf.get_connection_group(Identifier=cg_id)
            etag = current["ETag"]
            time.sleep(2)
    raise AssertionError(f"DeleteConnectionGroup({cg_id}) kept failing on a stale ETag")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
