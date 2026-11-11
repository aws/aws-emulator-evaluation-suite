"""associate-service-role-untrusted-role-is-accepted."""
from __future__ import annotations

import json

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "associate-service-role-untrusted-role-is-accepted"
GROUP = "overly-permissive"
SERVICES = ["greengrassv2"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:greengrass-service-role")
def run(ctx) -> None:
    """AssociateServiceRoleToAccount rejects a non-ARN roleArn with 400 and the exact message,
    leaving the association unchanged, and accepts a valid role ARN whose trust policy omits
    Greengrass.
    """
    gg = ctx.client("greengrassv2")
    iam = ctx.client("iam")

    try:
        original = gg.get_service_role_for_account()
        original_role_arn = original.get("roleArn")
    except ClientError as e:
        if e.response["Error"]["Code"] not in ("ResourceNotFoundException", "404"):
            raise
        original_role_arn = None

    def _restore_original():
        gg.disassociate_service_role_from_account()
        if original_role_arn:
            gg.associate_service_role_to_account(roleArn=original_role_arn)

    malformed_arn = "not-an-arn-" + ctx.unique_name("sim2real-ggv2-malformed-")
    code, message = _error_code(lambda: gg.associate_service_role_to_account(roleArn=malformed_arn))
    assert code == "400", f"got code={code!r}"
    expected = "That role ARN is invalid."
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    unchanged = _get_role_or_none(gg)
    assert unchanged != malformed_arn, unchanged

    untrusted_role_name = ctx.unique_name("sim2real-ggv2-untrusted-")
    untrusted_trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    untrusted_arn = iam.create_role(
        RoleName=untrusted_role_name,
        AssumeRolePolicyDocument=json.dumps(untrusted_trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=untrusted_role_name))
    ctx.on_cleanup(_restore_original)

    # Real AWS accepts this: trust-policy compatibility is not checked synchronously here.
    gg.associate_service_role_to_account(roleArn=untrusted_arn)
    _assert_eventually_associated(gg, untrusted_arn)


def _assert_eventually_associated(gg, expected_arn: str, timeout_s: float = 20.0, interval_s: float = 2.0) -> None:
    """Account-level service-role association is a singleton shared with other concurrently
    running checks; self-heal by re-asserting our own desired value until it sticks (survives
    transient interleaving with a sibling check's associate/disassociate)."""
    import time

    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = _get_role_or_none(gg)
        if last == expected_arn:
            return
        try:
            gg.associate_service_role_to_account(roleArn=expected_arn)
        except ClientError:
            pass
        time.sleep(interval_s)
    raise AssertionError(f"expected roleArn={expected_arn!r} to stick, last observed {last!r}")


def _get_role_or_none(gg):
    """GetServiceRoleForAccount raises a 404-ish ClientError when no role is currently
    associated (this is a real, empirically-observed AWS behavior, not an SDK modeling gap)."""
    try:
        return gg.get_service_role_for_account().get("roleArn")
    except ClientError as err:
        if err.response["Error"]["Code"] in ("ResourceNotFoundException", "404"):
            return None
        raise


def _error_code(fn):
    """Call fn(); return its error code and message. An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
