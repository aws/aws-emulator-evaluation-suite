"""iam-deny-calculate-routes-access-denied."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "iam-deny-calculate-routes-access-denied"
GROUP = "overly-permissive"
SERVICES = ["geo-routes"]

_SEATTLE = [-122.3321, 47.6062]
_PORTLAND = [-122.6784, 45.5152]


@tags("axis:rejection", "cap:c7", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """An identity allowed geo-routes:CalculateRoutes gets a route, an explicit Deny on the same identity
    turns the call into AccessDeniedException with its exact message, and lifting the Deny restores the route.
    """
    iam = ctx.client("iam")
    ctx.client("sts")
    user_name = ctx.unique_name("sim2real-behav-georoutes-deny-")

    user_arn = iam.create_user(UserName=user_name, Tags=[{"Key": "sim2real", "Value": CHECK}])[
        "User"
    ]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_user(UserName=user_name))

    policy_name = "calculate-routes-effect"

    def _put_policy(effect: str) -> None:
        iam.put_user_policy(
            UserName=user_name,
            PolicyName=policy_name,
            PolicyDocument=json.dumps(
                {
                    "Version": "2012-10-17",
                    "Statement": [
                        {"Effect": effect, "Action": "geo-routes:CalculateRoutes", "Resource": "*"}
                    ],
                }
            ),
        )

    _put_policy("Allow")
    ctx.on_cleanup(lambda: iam.delete_user_policy(UserName=user_name, PolicyName=policy_name))

    key = iam.create_access_key(UserName=user_name)["AccessKey"]
    ctx.on_cleanup(
        lambda: iam.delete_access_key(UserName=user_name, AccessKeyId=key["AccessKeyId"])
    )

    creds = {
        "aws_access_key_id": key["AccessKeyId"],
        "aws_secret_access_key": key["SecretAccessKey"],
    }
    as_user = ctx.client("geo-routes", creds=creds)
    as_user_sts = ctx.client("sts", creds=creds)

    # New IAM credentials take a few seconds to propagate; poll get_caller_identity (unaffected by the
    # geo-routes policy) as the readiness probe before the first assertion.
    _poll_until(lambda: _can_call(as_user_sts.get_caller_identity), timeout_s=30, interval_s=2)

    def _try_calculate():
        try:
            return as_user.calculate_routes(Origin=_SEATTLE, Destination=_PORTLAND, TravelMode="Car"), None
        except ClientError as err:
            return None, (err.response["Error"]["Code"], err.response["Error"].get("Message"))

    before = _poll(
        _try_calculate,
        lambda r: r[1] is None,
        timeout_s=60,
        interval_s=3,
        description="the allow policy becomes effective for geo-routes:CalculateRoutes",
    )
    assert before[1] is None and len(before[0]["Routes"]) >= 1, (
        f"the identity policy grants geo-routes:CalculateRoutes, so the real signed call must "
        f"succeed before any Deny is attached; got {before!r}"
    )

    _put_policy("Deny")
    denied = _poll(
        _try_calculate,
        lambda r: r[1] is not None,
        timeout_s=180,
        interval_s=3,
        description="the Deny statement blocks geo-routes:CalculateRoutes on the real signed call",
    )
    expected_denial = (
        "AccessDeniedException",
        f"User: {user_arn} is not authorized to perform: geo-routes:CalculateRoutes on resource: "
        f"arn:aws:geo-routes:{ctx.region}::provider/default with an explicit deny in an "
        f"identity-based policy",
    )
    assert denied[1] == expected_denial, (
        f"expected {expected_denial!r} once the Deny statement is attached, got {denied[1]!r}"
    )

    _put_policy("Allow")
    restored = _poll(
        _try_calculate,
        lambda r: r[1] is None,
        timeout_s=180,
        interval_s=3,
        description="removing the Deny statement restores geo-routes:CalculateRoutes",
    )
    assert restored[1] is None and len(restored[0]["Routes"]) >= 1, (
        f"the identical call must succeed again once the Deny statement is replaced by Allow; "
        f"got {restored!r}"
    )


def _can_call(fn) -> bool:
    try:
        fn()
        return True
    except ClientError:
        return False


def _poll_until(probe, *, timeout_s: float, interval_s: float) -> None:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        if probe():
            return
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s")


def _poll(probe, predicate, *, timeout_s: float, interval_s: float, description: str):
    deadline = time.monotonic() + timeout_s
    last = probe()
    while not predicate(last):
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"{description} not reached within {timeout_s}s; last error {last[1]!r}"
            )
        time.sleep(interval_s)
        last = probe()
    return last


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
