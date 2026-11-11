"""e2e-cluster-node-delete-then-reboot-fails."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "e2e-cluster-node-delete-then-reboot-fails"
GROUP = "state-machine"
SERVICES = ["sagemaker"]

_INSTANCE_TYPE = "ml.t3.medium"


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """After BatchDeleteClusterNodes removes a HyperPod node, BatchRebootClusterNodes naming only that
    node is refused with ValidationException "All provided nodes do not exist.", while rebooting the
    sibling node in the same cluster succeeds with no failed node ids.
    """
    sm = ctx.client("sagemaker")
    iam = ctx.client("iam")
    cluster_name = ctx.unique_name("sim2real-hpcluster-")
    group_name = "workers"
    controller_group = "controller"
    role_arn = _create_minimal_role(ctx, iam, "sagemaker.amazonaws.com")

    _create_cluster_with_role_retry(
        sm,
        ClusterName=cluster_name,
        InstanceGroups=[
            {
                "InstanceGroupName": controller_group,
                "InstanceType": _INSTANCE_TYPE,
                "InstanceCount": 1,
                "ExecutionRole": role_arn,
                "SlurmConfig": {"NodeType": "Controller"},
            },
            {
                "InstanceGroupName": group_name,
                "InstanceType": _INSTANCE_TYPE,
                "InstanceCount": 0,
                "ExecutionRole": role_arn,
                "SlurmConfig": {"NodeType": "Compute"},
            },
        ],
        NodeProvisioningMode="Continuous",
        Tags=[{"Key": "sim2real", "Value": "1"}],
    )
    ctx.on_cleanup(lambda: _delete_cluster_if_present(sm, cluster_name))

    cluster_status = _poll_until(
        lambda: sm.describe_cluster(ClusterName=cluster_name)["ClusterStatus"],
        lambda status: status in ("InService", "Failed"),
        timeout_s=900.0,
        interval_s=15.0,
    )
    assert cluster_status == "InService", (
        f"expected ClusterStatus=InService, got {cluster_status}: "
        f"{sm.describe_cluster(ClusterName=cluster_name).get('FailureMessage')}"
    )

    add_resp = sm.batch_add_cluster_nodes(
        ClusterName=cluster_name,
        NodesToAdd=[{"InstanceGroupName": group_name, "IncrementTargetCountBy": 2}],
    )
    assert not add_resp["Failed"], add_resp["Failed"]
    logical_ids = [r["NodeLogicalId"] for r in add_resp["Successful"]]
    assert len(logical_ids) == 2
    deleted_id, kept_id = logical_ids

    # Wait for the surviving node to actually be Running before we use it as our positive
    # control -- rebooting a node that never finished provisioning would not be a fair test.
    _poll_until(
        lambda: sm.describe_cluster_node(ClusterName=cluster_name, NodeLogicalId=kept_id)[
            "NodeDetails"
        ]["InstanceStatus"]["Status"],
        lambda status: status == "Running",
        timeout_s=600.0,
        interval_s=15.0,
    )

    del_resp = sm.batch_delete_cluster_nodes(
        ClusterName=cluster_name, NodeLogicalIds=[deleted_id]
    )
    assert deleted_id in del_resp.get("SuccessfulNodeLogicalIds", []), del_resp

    # The deleted node truly disappears: DescribeClusterNode stops finding it.
    _poll_until(
        lambda: _describe_node_or_none(sm, cluster_name, deleted_id),
        lambda node: node is None,
        timeout_s=180.0,
        interval_s=10.0,
    )

    # Negative: rebooting only the node that was just deleted is refused outright with
    # ValidationException (the raised ResourceNotFound is reserved for an unknown cluster,
    # not an unknown node in a real one).
    code, message = _error(
        lambda: sm.batch_reboot_cluster_nodes(ClusterName=cluster_name, NodeLogicalIds=[deleted_id])
    )
    assert code == "ValidationException", f"expected ValidationException, got {code}: {message!r}"
    expected = "All provided nodes do not exist. Please check the input and try again."
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Positive control: the SAME operation against the sibling node that still exists works.
    reboot_resp = sm.batch_reboot_cluster_nodes(
        ClusterName=cluster_name, NodeLogicalIds=[kept_id]
    )
    assert kept_id in reboot_resp.get("SuccessfulNodeLogicalIds", []), reboot_resp
    assert not reboot_resp.get("FailedNodeLogicalIds", []), reboot_resp


def _error(fn):
    """Call fn(); return its (code, message). A success raises: the call must be refused."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition never became true within {timeout_s}s (last={last!r})")


def _describe_node_or_none(sm, cluster_name, node_logical_id):
    from botocore.exceptions import ClientError

    try:
        return sm.describe_cluster_node(ClusterName=cluster_name, NodeLogicalId=node_logical_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "ResourceNotFound":
            return None
        raise


def _create_minimal_role(ctx, iam, service_principal: str) -> str:
    role_name = ctx.unique_name("sim2real-hp-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": service_principal},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    resp = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": "1"}],
    )
    iam.attach_role_policy(
        RoleName=role_name,
        PolicyArn="arn:aws:iam::aws:policy/AmazonSageMakerFullAccess",
    )
    ctx.on_cleanup(lambda: _delete_role(iam, role_name))
    return resp["Role"]["Arn"]


def _delete_role(iam, role_name):
    """Detach the managed policy, then delete the role; a missing one is already gone."""
    from botocore.exceptions import ClientError

    for step in (
        lambda: iam.detach_role_policy(
            RoleName=role_name, PolicyArn="arn:aws:iam::aws:policy/AmazonSageMakerFullAccess"
        ),
        lambda: iam.delete_role(RoleName=role_name),
    ):
        try:
            step()
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise


def _create_cluster_with_role_retry(sm, **kwargs):
    """CreateCluster can reject the freshly-created execution role until IAM's
    create-role has propagated to SageMaker; retry on that specific rejection rather than
    sleeping blindly, bounded so a genuine validation error still surfaces promptly."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + 60.0
    while True:
        try:
            sm.create_cluster(**kwargs)
            return
        except ClientError as exc:
            error = exc.response.get("Error", {})
            message = error.get("Message", "")
            if (
                error.get("Code") in ("ValidationException", "AccessDeniedException")
                and "role" in message.lower()
                and time.monotonic() < deadline
            ):
                time.sleep(5.0)
                continue
            raise


def _delete_cluster_if_present(sm, cluster_name):
    from botocore.exceptions import ClientError

    try:
        sm.delete_cluster(ClusterName=cluster_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFound":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
