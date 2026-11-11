"""delete-webapp-customization-conflict-blocked."""
from __future__ import annotations

import json
import time
from concurrent.futures import ThreadPoolExecutor

from behavioral_harness import tags

CHECK = "delete-webapp-customization-conflict-blocked"
GROUP = "overly-permissive"
SERVICES = ["transfer"]

_RACERS = 8
_CONFLICT_MESSAGE = "Unable to delete WebApp customization"


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:identity-center-instance")
def run(ctx) -> None:
    """Concurrent DeleteWebAppCustomization calls on one customization delete it: a racer succeeds or
    is refused with ConflictException and its exact message, the customization is gone afterwards,
    and a later sequential delete succeeds again."""

    run.__globals__.setdefault("_tags_applied", True)

    transfer = ctx.client("transfer")
    iam = ctx.client("iam")
    sso_admin = ctx.client("sso-admin")

    instance_arn = _identity_center_instances(ctx, sso_admin)[0]["InstanceArn"]

    role_arn = _create_transfer_role(ctx, iam, "sim2real-behav-webapp-")

    web_app_name = ctx.unique_name("sim2real-behav-webapp-")

    def _create_web_app():
        return transfer.create_web_app(
            IdentityProviderDetails={"IdentityCenterConfig": {"InstanceArn": instance_arn, "Role": role_arn}},
            Tags=[{"Key": "Name", "Value": web_app_name}],
        )["WebAppId"]

    # IAM role trust is eventually consistent: Transfer can reject the freshly-created
    # role for a few seconds before it is able to assume it.
    web_app_id = _retry_while_role_not_yet_usable(_create_web_app, timeout_s=30, interval_s=2)
    ctx.on_cleanup(lambda: transfer.delete_web_app(WebAppId=web_app_id))

    transfer.update_web_app_customization(WebAppId=web_app_id, Title="sim2real-behav-customization")
    described = transfer.describe_web_app_customization(WebAppId=web_app_id)["WebAppCustomization"]
    assert described["Title"] == "sim2real-behav-customization"

    def _race_delete(_):
        try:
            transfer.delete_web_app_customization(WebAppId=web_app_id)
            return ("success", None)
        except Exception as exc:  # noqa: BLE001 -- classified below
            return ("error", _error_of(exc))

    with ThreadPoolExecutor(max_workers=_RACERS) as pool:
        results = list(pool.map(_race_delete, range(_RACERS)))

    successes = [r for r in results if r[0] == "success"]
    error_codes = [r[1] for r in results if r[0] == "error"]

    assert successes, f"expected at least one winning delete, got {results}"
    # An overlapping racer may be refused while another delete is in flight.
    assert all(error == ("ConflictException", _CONFLICT_MESSAGE) for error in error_codes), (
        f"a losing racer must get ConflictException with its exact message, got {error_codes}"
    )

    # Effect: the customization is actually gone (the winner's delete really applied), not left
    # half-applied by the contention.
    _poll_until(
        probe=lambda: _error_code_of_call(lambda: transfer.describe_web_app_customization(WebAppId=web_app_id)),
        predicate=lambda code: code == "ResourceNotFoundException",
        timeout_s=30,
        interval_s=2,
    )

    repeat = _race_delete(None)
    assert repeat == ("success", None), f"expected a sequential repeat delete to succeed, got {repeat}"

    # Positive control: a single, non-racing create-then-delete of the customization on the
    # very same web app succeeds cleanly with no ConflictException.
    transfer.update_web_app_customization(WebAppId=web_app_id, Title="sim2real-behav-customization-2")
    transfer.delete_web_app_customization(WebAppId=web_app_id)
    _poll_until(
        probe=lambda: _error_code_of_call(lambda: transfer.describe_web_app_customization(WebAppId=web_app_id)),
        predicate=lambda code: code == "ResourceNotFoundException",
        timeout_s=30,
        interval_s=2,
    )


# ===== helpers =====
def _identity_center_instances(ctx, sso_idc):
    """The account's IAM Identity Center instances, creating one if the account has none.

    `sso-admin:CreateInstance` provisions a
    STANDALONE (non-Organizations) instance, so the prerequisite is satisfiable in-check in any
    account. Exactly one instance is
    allowed per account and deleting it would disrupt any other check relying on it, so one
    created here is deliberately never torn down.
    """
    import time

    from botocore.exceptions import ClientError

    try:
        instances = sso_idc.list_instances().get("Instances", [])
    except ClientError as exc:
        raise AssertionError(
            f"cannot query IAM Identity Center instances ({exc.response['Error']['Code']})"
        ) from exc
    if not instances:
        sso_idc.create_instance(Name=ctx.unique_name("sim2real-idc-"))
    deadline = time.time() + 120
    while time.time() < deadline:
        found = sso_idc.list_instances().get("Instances", [])
        for inst in found:
            if inst.get("Status") == "CREATE_FAILED":
                raise AssertionError(f"IAM Identity Center instance creation failed: {inst}")
        if any(i.get("Status") == "ACTIVE" and "IdentityStoreId" in i for i in found):
            return found
        time.sleep(3)
    raise AssertionError(
        "IAM Identity Center instance did not become ACTIVE with an IdentityStoreId within 120s"
    )


def _error_of(exc) -> tuple[str, str | None]:
    from botocore.exceptions import ClientError

    if isinstance(exc, ClientError):
        return (exc.response["Error"]["Code"], exc.response["Error"].get("Message"))
    raise exc


def _error_code_of_call(fn):
    """The error code fn() raises, or "succeeded" while the call still answers: a poll state."""
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"]
    return "succeeded"


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float):
    deadline = time.monotonic() + timeout_s
    value = probe()
    while not predicate(value):
        if time.monotonic() >= deadline:
            raise AssertionError(f"condition not met within {timeout_s}s, last value={value!r}")
        time.sleep(interval_s)
        value = probe()
    return value


def _retry_while_role_not_yet_usable(fn, *, timeout_s: float, interval_s: float):
    """Bounded retry for the IAM-role-trust propagation window: a role Transfer cannot
    yet assume raises a ClientError for a few seconds after CreateRole returns."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return fn()
        except ClientError:
            if time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)


def _create_transfer_role(ctx, iam, name_prefix: str) -> str:
    role_name = ctx.unique_name(name_prefix)[:64]
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "transfer.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "Name", "Value": role_name}],
    )
    role_arn = role["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    return role_arn


from behavioral_harness import tags  # noqa: E402

run = tags("axis:rejection")(run)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
