"""create-cluster-scheduler-config-nonexistent-cluster-rejected."""
from __future__ import annotations

import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-cluster-scheduler-config-nonexistent-cluster-rejected"
GROUP = "error-semantics"
SERVICES = ["sagemaker"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateClusterSchedulerConfig with a malformed ClusterArn and with a well-formed nonexistent one
    each fails with ValidationException and its exact message, and no config is created."""
    sm = ctx.client("sagemaker")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    name = ctx.unique_name("sim2real-csc-noexist-")

    # Structurally invalid ClusterArn (still >= botocore's client-side length
    # floor, so it reaches the server rather than short-circuiting locally).
    malformed_arn = "not-an-arn-at-all-0123456789"
    malformed_code, malformed_message = _error(
        lambda: sm.create_cluster_scheduler_config(
            Name=name, ClusterArn=malformed_arn, SchedulerConfig={}
        )
    )
    assert malformed_code == "ValidationException", (
        f"expected a malformed ClusterArn to be rejected with ValidationException, got {malformed_code!r}"
    )
    expected_malformed = (
        f"1 validation error detected: Value '{malformed_arn}' at 'clusterArn' failed to satisfy "
        "constraint: Member must satisfy regular expression pattern: "
        r"arn:aws[a-z\-]*:sagemaker:[a-z0-9\-]*:[0-9]{12}:cluster/[a-z0-9]{12}"
    )
    assert malformed_message == expected_malformed, (
        f"expected message {expected_malformed!r}, got {malformed_message!r}"
    )

    # Syntactically well-formed (matches the documented ARN pattern) but the
    # embedded cluster id is entirely made up.
    fake_cluster_id = uuid.uuid4().hex[:12]
    cluster_arn = f"arn:aws:sagemaker:{ctx.region}:{account_id}:cluster/{fake_cluster_id}"
    code, message = _error(
        lambda: sm.create_cluster_scheduler_config(
            Name=name, ClusterArn=cluster_arn, SchedulerConfig={}
        )
    )
    assert code == "ValidationException", f"expected ValidationException, got {code!r}"
    expected = "Specified cluster not found"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Effect absent: no config was created under that name, for either attempt.
    listed = sm.list_cluster_scheduler_configs(NameContains=name)["ClusterSchedulerConfigSummaries"]
    assert not listed, f"expected no cluster scheduler config for name={name!r}, found {listed!r}"

    # Sanity control: the general capability (List) still works normally --
    # the account/credentials are not broadly broken.
    sm.list_cluster_scheduler_configs()


def _error(fn):
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

