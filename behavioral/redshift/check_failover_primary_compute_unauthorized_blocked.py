"""failover-primary-compute-unauthorized-blocked."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "failover-primary-compute-unauthorized-blocked"
GROUP = "overly-permissive"
SERVICES = ["redshift"]


@tags("axis:rejection", "cap:c7", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """FailoverPrimaryCompute is AccessDenied for a caller with no IAM permissions while an authorized
    caller gets ClusterNotFound; granting that same identity the action restores ClusterNotFound.
    """
    redshift = ctx.client("redshift")
    iam = ctx.client("iam")
    fake_cluster_id = ctx.unique_name("sim2real-behav-failover-")

    # Positive control FIRST: an authorized caller's identical call reaches the
    # service layer and fails only because the cluster does not exist -- this
    # proves the call path itself works and isolates the permission boundary as
    # the only thing under test below.
    not_found_message = f"Cluster not found: {fake_cluster_id}"
    control_code, control_message = _error_detail(
        lambda: redshift.failover_primary_compute(ClusterIdentifier=fake_cluster_id)
    )
    assert control_code == "ClusterNotFound", (
        f"expected ClusterNotFound for the authorized control call, got {control_code}"
    )
    assert control_message == not_found_message, (
        f"expected message {not_found_message!r}, got {control_message!r}"
    )

    # Break exactly one thing: a brand-new IAM user with no attached policies at
    # all making the same call.
    user_name = ctx.unique_name("sim2real-behav-noperm-")
    iam.create_user(UserName=user_name, Tags=[{"Key": "sim2real", "Value": CHECK}])
    ctx.on_cleanup(lambda: iam.delete_user(UserName=user_name))
    key = iam.create_access_key(UserName=user_name)["AccessKey"]
    ctx.on_cleanup(
        lambda: iam.delete_access_key(UserName=user_name, AccessKeyId=key["AccessKeyId"])
    )

    restricted = ctx.client(
        "redshift",
        creds={
            "aws_access_key_id": key["AccessKeyId"],
            "aws_secret_access_key": key["SecretAccessKey"],
        },
    )

    # New IAM credentials can take a few seconds to become usable. Poll past any
    # transient "credentials not yet active" signature errors and assert on the
    # actual authorization outcome.
    code, message = _poll_until(
        restricted,
        fake_cluster_id,
        lambda c: c == "AccessDenied",
        timeout_s=30.0,
        description="the no-permission caller is denied",
    )
    assert code == "AccessDenied", f"expected AccessDenied, got {code}"
    expected_denied = (
        f"User: arn:aws:iam::{ctx.account}:user/{user_name} is not authorized to perform: "
        f"redshift:FailoverPrimaryCompute on resource: "
        f"arn:aws:redshift:{ctx.region}:{ctx.account}:cluster:{fake_cluster_id} "
        "because no identity-based policy allows the redshift:FailoverPrimaryCompute action"
    )
    assert message == expected_denied, f"expected message {expected_denied!r}, got {message!r}"

    # Restore: grant the SAME identity exactly the action under test, and demand
    # the identical call now reaches the same ClusterNotFound outcome as the
    # authorized control -- proving the IAM policy, not something else about
    # this identity or this call, was the only thing blocking it.
    policy_name = ctx.unique_name("sim2real-behav-noperm-grant-")
    iam.put_user_policy(
        UserName=user_name,
        PolicyName=policy_name,
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": "redshift:FailoverPrimaryCompute",
                        "Resource": "*",
                    }
                ],
            }
        ),
    )
    ctx.on_cleanup(lambda: iam.delete_user_policy(UserName=user_name, PolicyName=policy_name))

    # IAM identity-policy propagation to Redshift's own authorization path is
    # eventually consistent and can take minutes, even when the policy simulator
    # already reports the grant effective.
    restored_code, restored_message = _poll_until(
        restricted,
        fake_cluster_id,
        lambda c: c != "AccessDenied",
        timeout_s=260.0,
        description="the grant becomes effective and the call reaches the service layer",
    )
    assert restored_code == "ClusterNotFound", (
        f"expected ClusterNotFound once redshift:FailoverPrimaryCompute is granted, "
        f"got {restored_code}"
    )
    assert restored_message == not_found_message, (
        f"expected message {not_found_message!r}, got {restored_message!r}"
    )


def _error_detail(fn):
    """Call fn(); return (code, message) of its ClientError. An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


_CREDENTIAL_PROPAGATION_CODES = (
    "InvalidClientTokenId",
    "InvalidAccessKeyId",
    "SignatureDoesNotMatch",
)


def _poll_until(restricted_client, cluster_id, predicate, timeout_s, description, interval_s=2.0):
    """Poll the identical call until ``predicate(code)`` holds, tolerating IAM's
    eventual consistency for both fresh credentials and freshly-granted policies.
    Raises on timeout -- it never hands back a stale last observation as if it
    were the terminal one."""
    deadline = time.monotonic() + timeout_s
    last_code = None
    last_message = None
    while time.monotonic() < deadline:
        last_code, last_message = _error_detail(
            lambda: restricted_client.failover_primary_compute(ClusterIdentifier=cluster_id)
        )
        if predicate(last_code):
            return last_code, last_message
        if last_code in _CREDENTIAL_PROPAGATION_CODES or last_code == "AccessDenied":
            time.sleep(interval_s)
            continue
        return last_code, last_message
    raise AssertionError(
        f"{description} not reached within {timeout_s}s; "
        f"last observation {last_code!r}: {last_message!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
