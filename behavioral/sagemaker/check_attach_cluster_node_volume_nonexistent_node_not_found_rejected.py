"""attach-cluster-node-volume-nonexistent-node-not-found-rejected."""
from __future__ import annotations

import random
import string

from behavioral_harness import tags

CHECK = "attach-cluster-node-volume-nonexistent-node-not-found-rejected"
GROUP = "error-semantics"
SERVICES = ["sagemaker"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """AttachClusterNodeVolume on a well-formed nonexistent cluster, node and volume fails with
    ValidationException and the exact message, while DescribeClusterNode on the same target fails
    with ResourceNotFound and its exact message."""
    sm = ctx.client("sagemaker")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]
    cluster_id = "".join(random.choices(string.ascii_lowercase + string.digits, k=12))
    cluster_arn = f"arn:aws:sagemaker:{ctx.region}:{account_id}:cluster/{cluster_id}"
    node_id = "i-" + "".join(random.choices("0123456789abcdef", k=17))
    # A non-zero leading digit puts the 17-digit id outside the range EC2 issues.
    volume_id = "vol-f" + "".join(random.choices("0123456789abcdef", k=16))

    code, message = _error(lambda: sm.attach_cluster_node_volume(ClusterArn=cluster_arn, NodeId=node_id, VolumeId=volume_id))
    assert code == "ValidationException", f"expected ValidationException, got {code!r}"
    expected = (
        f"HyperPod - EC2ErrCode: InvalidParameterValue : Value ({volume_id}) for parameter volumes is invalid. "
        "Expected: 'vol-...'."
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Independent read on the same unresolvable target: DescribeClusterNode answers the documented
    # ResourceNotFound, so the ValidationException is specific to attach's precondition check.
    absent_code, absent_message = _error(lambda: sm.describe_cluster_node(ClusterName=cluster_arn, NodeId=node_id))
    assert absent_code == "ResourceNotFound", f"expected ResourceNotFound, got {absent_code!r}"
    expected_absent = "Specified cluster node not found"
    assert absent_message == expected_absent, f"expected message {expected_absent!r}, got {absent_message!r}"


def _error(fn):
    """Return (code, message) of the call's ClientError; an unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected this call to fail, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
