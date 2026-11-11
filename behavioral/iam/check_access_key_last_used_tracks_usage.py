"""access-key-last-used-tracks-usage."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "access-key-last-used-tracks-usage"
GROUP = "server-side"
SERVICES = ["iam"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A never-used key reports no LastUsedDate and 'N/A' ServiceName/Region in GetAccessKeyLastUsed.

    IAM usage tracking lags minutes to hours, so the post-use 'sts' state is checked only if it
    appears; an unconverged response must still be exactly the 'N/A' shape.
    """
    iam = ctx.client("iam")
    user_name = ctx.unique_name("sim2real-akl-user-")
    iam.create_user(UserName=user_name, Tags=[{"Key": "sim2real", "Value": CHECK}])
    ctx.on_cleanup(lambda: iam.delete_user(UserName=user_name))

    key = iam.create_access_key(UserName=user_name)["AccessKey"]
    access_key_id = key["AccessKeyId"]
    secret_key = key["SecretAccessKey"]
    ctx.on_cleanup(lambda: iam.delete_access_key(UserName=user_name, AccessKeyId=access_key_id))

    never_used = iam.get_access_key_last_used(AccessKeyId=access_key_id)
    assert never_used["UserName"] == user_name, (
        f"expected UserName {user_name!r}, got {never_used['UserName']!r}"
    )
    lu = never_used["AccessKeyLastUsed"]
    assert "LastUsedDate" not in lu, f"expected no LastUsedDate before first use, got {lu!r}"
    assert lu["ServiceName"] == "N/A", f"expected sentinel ServiceName 'N/A', got {lu['ServiceName']!r}"
    assert lu["Region"] == "N/A", f"expected sentinel Region 'N/A', got {lu['Region']!r}"

    # Usage tracking can take minutes to hours, so the poll below is opportunistic.
    temp_sts = ctx.client(
        "sts",
        creds={"aws_access_key_id": access_key_id, "aws_secret_access_key": secret_key},
    )
    _wait_for_key_propagation(temp_sts)
    identity = temp_sts.get_caller_identity()
    assert identity["Arn"].endswith(f"user/{user_name}"), (
        f"expected the signed call to authenticate as {user_name!r}, got {identity['Arn']!r}"
    )

    populated = _poll_until(
        lambda: iam.get_access_key_last_used(AccessKeyId=access_key_id)["AccessKeyLastUsed"],
        lambda d: "LastUsedDate" in d,
        timeout_s=60.0,
        interval_s=5.0,
    )
    if "LastUsedDate" in populated:
        assert populated["ServiceName"] == "sts", (
            f"expected ServiceName 'sts' once tracked, got {populated['ServiceName']!r}"
        )
        assert populated["Region"] != "N/A", "expected a real Region once tracked, got sentinel 'N/A'"
    else:
        # Not converged yet (the common case): the response must still be the exact not-yet-used
        # shape, so a target that fabricates values once the key is used is still caught.
        assert populated["ServiceName"] == "N/A", (
            f"not yet converged, but ServiceName is neither tracked nor the sentinel: {populated!r}"
        )
        assert populated["Region"] == "N/A", (
            f"not yet converged, but Region is neither tracked nor the sentinel: {populated!r}"
        )


def _poll_until(probe, predicate, *, timeout_s=30.0, interval_s=1.5):
    deadline = time.monotonic() + timeout_s
    last = {}
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    return last


def _wait_for_key_propagation(temp_sts, timeout_s=20.0, interval_s=2.0):
    """A just-created access key can take a few seconds to become usable account-wide."""
    from botocore.exceptions import ClientError
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            temp_sts.get_caller_identity()
            return
        except ClientError:
            time.sleep(interval_s)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
