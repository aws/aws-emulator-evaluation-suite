"""failover-primary-compute-unauthorized-denied."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "failover-primary-compute-unauthorized-denied"
GROUP = "overly-permissive"
SERVICES = ["redshift"]


@tags("axis:rejection", "cap:c7", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """FailoverPrimaryCompute by an IAM identity with no permissions is AccessDenied before the
    nonexistent cluster is looked up, while a fully privileged caller gets past authorization.
    """
    redshift = ctx.client("redshift")
    bogus_cluster_id = ctx.unique_name("sim2real-failover-ghost-")

    # Positive control: a fully-privileged caller reaches business logic (the
    # cluster lookup) rather than being denied -- proves this isn't a universally
    # broken/blocked operation.
    control_code, control_message = _error(
        lambda: redshift.failover_primary_compute(ClusterIdentifier=bogus_cluster_id)
    )
    assert control_code == "ClusterNotFound", (
        f"expected the fully-privileged control call to reach business logic with "
        f"ClusterNotFound, got {control_code!r}"
    )
    expected = f"Cluster not found: {bogus_cluster_id}"
    assert control_message == expected, f"expected message {expected!r}, got {control_message!r}"

    user_name = ctx.unique_name("sim2real-failover-user-")
    iam = ctx.client("iam")
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

    # New IAM credentials propagate to each AWS service's own credential cache on its
    # own schedule -- confirming readiness against STS does not guarantee Redshift has
    # caught up too, so poll the actual call under test and tolerate only the
    # transient "credentials not yet recognized" codes, never the terminal one.
    code, message = _poll_until_terminal(
        lambda: _error(
            lambda: restricted.failover_primary_compute(ClusterIdentifier=bogus_cluster_id)
        ),
        timeout_s=30.0,
    )
    assert code == "AccessDenied", f"expected AccessDenied, got {code!r}"
    expected = (
        f"User: arn:aws:iam::{ctx.account}:user/{user_name} is not authorized to perform: "
        f"redshift:FailoverPrimaryCompute on resource: "
        f"arn:aws:redshift:{ctx.region}:{ctx.account}:cluster:{bogus_cluster_id} "
        "because no identity-based policy allows the redshift:FailoverPrimaryCompute action"
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"


def _error(fn):
    """Call fn(); return (code, message) of its ClientError. An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


_CREDENTIALS_NOT_YET_READY = ("InvalidClientTokenId", "InvalidAccessKeyId", "SignatureDoesNotMatch")


def _poll_until_terminal(probe, *, timeout_s, interval_s=2.0):
    """Retry while the new IAM credentials are still propagating to THIS service's
    own credential cache; return as soon as the code is a real (non-propagation)
    outcome, and raise rather than silently returning a not-yet-ready code."""
    deadline = time.monotonic() + timeout_s
    last_code = None
    while time.monotonic() < deadline:
        last_code, last_message = probe()
        if last_code not in _CREDENTIALS_NOT_YET_READY:
            return last_code, last_message
        time.sleep(interval_s)
    raise AssertionError(
        f"new IAM access key never became usable against this service: {last_code!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
