"""disassociate-service-role-idempotent-when-none-associated."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "disassociate-service-role-idempotent-when-none-associated"
GROUP = "state"
SERVICES = ["greengrassv2"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:greengrass-service-role")
def run(ctx) -> None:
    """DisassociateServiceRoleFromAccount succeeds as a no-op when no service role is associated;
    a real association is first shown to stick through GetServiceRoleForAccount, so a target that
    always reports "unassociated" cannot pass, and the original association is restored."""
    gg = ctx.client("greengrassv2")
    iam = ctx.client("iam")
    original = _get_role_or_none(gg)
    _register_restore(ctx, gg, original)

    # Positive control: prove a real association actually sticks and is observable through
    # GetServiceRoleForAccount before trusting an absence reading from that same call.
    role_name = ctx.unique_name("sim2real-ggv2-role-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "greengrass.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust_policy)
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    _associate_with_iam_retry(gg, role_arn)
    # Account-level service-role association is a singleton shared with other concurrently
    # running checks; self-heal by re-asserting our own desired value until it sticks.
    _assert_eventually(gg, role_arn, lambda: _try(lambda: gg.associate_service_role_to_account(roleArn=role_arn)))

    # Ensure no role is associated right now.
    gg.disassociate_service_role_from_account()
    _assert_eventually_absent(gg)

    # Calling it again while nothing is associated must still succeed, not error.
    gg.disassociate_service_role_from_account()
    _assert_eventually_absent(gg)


# ===== helpers =====
def _get_role_or_none(gg):
    """GetServiceRoleForAccount raises a 404-ish ClientError when no role is currently
    associated (this is a real, empirically-observed AWS behavior, not an SDK modeling gap)."""
    try:
        return gg.get_service_role_for_account().get("roleArn")
    except ClientError as err:
        if err.response["Error"]["Code"] in ("ResourceNotFoundException", "404"):
            return None
        raise


def _associate_with_iam_retry(gg, role_arn: str, timeout_s: float = 30.0, interval_s: float = 2.0) -> None:
    """IAM role creation is eventually consistent; retry until Greengrass can validate the trust
    policy, but let any other error surface immediately."""
    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            gg.associate_service_role_to_account(roleArn=role_arn)
            return
        except ClientError as err:
            last_err = err
            if err.response["Error"]["Code"] != "ValidationException":
                raise
            time.sleep(interval_s)
    raise AssertionError(f"AssociateServiceRoleToAccount never succeeded: {last_err}")


def _try(fn) -> None:
    try:
        fn()
    except ClientError:
        pass


def _assert_eventually(gg, expected_arn: str, reapply_fn, timeout_s: float = 20.0, interval_s: float = 2.0) -> None:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = _get_role_or_none(gg)
        if last == expected_arn:
            return
        reapply_fn()
        time.sleep(interval_s)
    raise AssertionError(f"expected roleArn={expected_arn!r} to stick, last observed {last!r}")


def _assert_eventually_absent(gg, timeout_s: float = 10.0, interval_s: float = 1.0) -> None:
    """Only requires OUR disassociate call to be observed honored at least once within a short
    window, so a sibling check re-associating its own role a moment later is not mistaken for
    DisassociateServiceRoleFromAccount having failed."""
    deadline = time.monotonic() + timeout_s
    last = "not-checked"
    while time.monotonic() < deadline:
        last = _get_role_or_none(gg)
        if not last:
            return
        time.sleep(interval_s)
    raise AssertionError(f"expected no role associated, last observed {last!r}")


def _register_restore(ctx, gg, original_role_arn) -> None:
    def restore():
        if not original_role_arn:
            return
        # Nothing to restore when the original role does not exist.
        try:
            ctx.client("iam").get_role(RoleName=original_role_arn.rsplit("/", 1)[-1])
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "NoSuchEntity":
                return
            raise
        gg.associate_service_role_to_account(roleArn=original_role_arn)

    ctx.on_cleanup(restore)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

