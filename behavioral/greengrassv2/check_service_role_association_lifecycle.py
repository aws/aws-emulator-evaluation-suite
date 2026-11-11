"""service-role-association-lifecycle."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "service-role-association-lifecycle"
GROUP = "state"
SERVICES = ["greengrassv2"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:greengrass-service-role")
def run(ctx) -> None:
    """Associate/GetServiceRoleForAccount/Disassociate form a full account-level role lifecycle."""
    ggv2 = ctx.client("greengrassv2")
    iam = ctx.client("iam")

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
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    _associate_with_iam_retry(ggv2, role_arn)
    ctx.on_cleanup(ggv2.disassociate_service_role_from_account)

    # Account-level service-role association is a singleton shared with other concurrently
    # running checks; self-heal by re-asserting our own desired value until it sticks.
    _assert_eventually(ggv2, lambda: ggv2.associate_service_role_to_account(roleArn=role_arn), role_arn)

    ggv2.disassociate_service_role_from_account()

    # After disassociating, self-heal against sibling checks re-associating: only require that
    # OUR disassociate call itself is honored at least once (poll briefly for the empty state).
    _poll_until(
        lambda: _get_role_or_none(ggv2),
        lambda arn: not arn,
        timeout_s=10.0,
        interval_s=1.0,
    )


# ===== helpers =====

def _associate_with_iam_retry(ggv2, role_arn: str, timeout_s: float = 30.0, interval_s: float = 2.0) -> None:
    """IAM role creation is eventually consistent; retry until Greengrass can validate the trust policy."""
    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            ggv2.associate_service_role_to_account(roleArn=role_arn)
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


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s, last={last!r}")


def _assert_eventually(ggv2, reapply_fn, expected_arn: str, timeout_s: float = 20.0, interval_s: float = 2.0) -> None:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = _get_role_or_none(ggv2)
        if last == expected_arn:
            return
        _try(reapply_fn)
        time.sleep(interval_s)
    raise AssertionError(f"expected roleArn={expected_arn!r} to stick, last observed {last!r}")


def _get_role_or_none(ggv2):
    """GetServiceRoleForAccount raises a 404-ish ClientError when no role is currently
    associated (this is a real, empirically-observed AWS behavior, not an SDK modeling gap)."""
    try:
        return ggv2.get_service_role_for_account().get("roleArn")
    except ClientError as err:
        if err.response["Error"]["Code"] in ("ResourceNotFoundException", "404"):
            return None
        raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)


