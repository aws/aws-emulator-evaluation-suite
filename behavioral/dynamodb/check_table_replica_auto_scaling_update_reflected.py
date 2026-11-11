"""table-replica-auto-scaling-update-reflected."""
from __future__ import annotations

import json
import time
from typing import Any, Callable

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "table-replica-auto-scaling-update-reflected"
GROUP = "state-machine"
SERVICES = ["dynamodb"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateTableReplicaAutoScaling via DynamoDB's default service-linked role is reflected by
    DescribeTableReplicaAutoScaling, while a customer AutoScalingRoleArn is refused with a
    ValidationException wrapping an iam:PassRole denial and changes nothing.
    """
    # One teardown deadline per run, started by the first teardown that runs.
    teardown_deadline: dict = {}
    ddb = ctx.client("dynamodb")
    iam = ctx.client("iam")
    aas = ctx.client("application-autoscaling")

    role_arn = _create_autoscaling_role(ctx, iam)

    table_name = ctx.unique_name("sim2real-behav-tras-")
    ddb.create_table(
        TableName=table_name,
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        BillingMode="PROVISIONED",
        ProvisionedThroughput={"ReadCapacityUnits": 5, "WriteCapacityUnits": 5},
        StreamSpecification={"StreamEnabled": True, "StreamViewType": "NEW_AND_OLD_IMAGES"},
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _safe_delete_table(ddb, table_name, teardown_deadline))
    _poll_until(
        lambda: ddb.describe_table(TableName=table_name)["Table"]["TableStatus"],
        lambda status: status == "ACTIVE",
        timeout_s=60,
        interval_s=2,
    )

    # A PROVISIONED table needs auto-scaled write capacity before a replica can be added.
    _register_write_capacity_autoscaling(ctx, aas, table_name)

    # DescribeTableReplicaAutoScaling only recognizes global tables, so add a replica
    # (global tables version 2019.11.21; DynamoDB creates the remote table itself).
    region2 = _secondary_region(ctx.region)
    _create_replica_with_retry(ddb, table_name, region2)
    ctx.on_cleanup(lambda: _safe_remove_replica(ddb, table_name, region2, teardown_deadline))
    # DescribeGlobalTable (version 2017.11.29) never finds a 2019.11.21 replica, so readiness
    # is read from DescribeTable's Replicas[].ReplicaStatus.
    _poll_until(
        lambda: ddb.describe_table(TableName=table_name)["Table"],
        lambda table: table["TableStatus"] == "ACTIVE"
        and any(
            r["RegionName"] == region2 and r["ReplicaStatus"] == "ACTIVE"
            for r in table.get("Replicas", [])
        ),
        timeout_s=280,
        interval_s=10,
    )

    baseline = _poll_until(
        lambda: ddb.describe_table_replica_auto_scaling(TableName=table_name)[
            "TableAutoScalingDescription"
        ],
        lambda desc: desc["TableStatus"] == "ACTIVE",
        timeout_s=120,
        interval_s=5,
    )
    assert any(r["RegionName"] == ctx.region for r in baseline["Replicas"]), (
        f"expected a replica in {ctx.region}, got regions "
        f"{[r['RegionName'] for r in baseline['Replicas']]}"
    )

    def _write_scaling_settings(expected_max: int) -> Callable[[], dict[str, Any] | None]:
        def _probe() -> dict[str, Any] | None:
            desc = ddb.describe_table_replica_auto_scaling(TableName=table_name)[
                "TableAutoScalingDescription"
            ]
            for replica in desc["Replicas"]:
                if replica["RegionName"] == ctx.region:
                    settings = replica.get("ReplicaProvisionedWriteCapacityAutoScalingSettings")
                    if settings and settings.get("MaximumUnits") == expected_max:
                        return settings
            return None

        return _probe

    # Positive control: the same call without AutoScalingRoleArn uses the service-linked role.
    control_policy_name = ctx.unique_name("sim2real-behav-tras-control-policy-")
    control_resp = ddb.update_table_replica_auto_scaling(
        TableName=table_name,
        ProvisionedWriteCapacityAutoScalingUpdate={
            "MinimumUnits": 5,
            "MaximumUnits": 12,
            "ScalingPolicyUpdate": {
                "PolicyName": control_policy_name,
                "TargetTrackingScalingPolicyConfiguration": {
                    "TargetValue": 55.0,
                    "ScaleInCooldown": 60,
                    "ScaleOutCooldown": 60,
                },
            },
        },
    )
    ctx.on_cleanup(
        lambda: _safe_delete_scaling_policy(
            aas, control_policy_name, f"table/{table_name}", "dynamodb:table:WriteCapacityUnits"
        )
    )
    assert control_resp["TableAutoScalingDescription"]["TableName"] == table_name, (
        f"expected TableName={table_name!r}, got "
        f"{control_resp['TableAutoScalingDescription'].get('TableName')!r}"
    )

    control_settings = _poll_until(
        _write_scaling_settings(12), lambda s: s is not None, timeout_s=90, interval_s=5
    )
    assert control_settings["MinimumUnits"] == 5, (
        f"expected MinimumUnits=5, got {control_settings['MinimumUnits']}"
    )
    assert control_settings["MaximumUnits"] == 12, (
        f"expected MaximumUnits=12, got {control_settings['MaximumUnits']}"
    )
    control_role_arn = control_settings["AutoScalingRoleArn"]
    assert control_role_arn != role_arn, (
        f"positive control should bind DynamoDB's own managed role, not our custom {role_arn!r}"
    )
    assert "AWSServiceRoleForApplicationAutoScaling" in control_role_arn, (
        f"expected DynamoDB's managed autoscaling service-linked role, got {control_role_arn!r}"
    )

    # AWSServiceRoleForDynamoDBReplication's managed policy never grants iam:PassRole on a
    # customer role, so one attempt is definitive. AWS returns its own ValidationException with
    # the Application Auto Scaling AccessDeniedException embedded in the message.
    policy_name = ctx.unique_name("sim2real-behav-tras-policy-")
    try:
        ddb.update_table_replica_auto_scaling(
            TableName=table_name,
            ProvisionedWriteCapacityAutoScalingUpdate={
                "MinimumUnits": 5,
                "MaximumUnits": 15,
                "AutoScalingRoleArn": role_arn,
                "ScalingPolicyUpdate": {
                    "PolicyName": policy_name,
                    "TargetTrackingScalingPolicyConfiguration": {
                        "TargetValue": 55.0,
                        "ScaleInCooldown": 60,
                        "ScaleOutCooldown": 60,
                    },
                },
            },
        )
    except Exception as exc:  # noqa: BLE001
        code = _error_code_from_exc(exc)
        message = str(exc)
        assert code == "ValidationException", (
            f"expected ValidationException for a customer AutoScalingRoleArn on a table "
            f"replica, got {code}: {message}"
        )
        assert "iam:PassRole" in message and "AccessDeniedException" in message, (
            f"expected a ValidationException wrapping an iam:PassRole AccessDeniedException, "
            f"got: {message}"
        )
        assert role_arn in message, (
            f"expected the denial to name our custom role {role_arn!r}, got: {message}"
        )
        # The caller's role/session names and the wrapped request id are not values the check holds.
        aws_message = exc.response["Error"].get("Message", "")
        account = role_arn.split(":")[4]
        denial = (
            f" is not authorized to perform: iam:PassRole on resource: {role_arn} because no "
            "identity-based policy allows the iam:PassRole action (Service: "
        )
        assert (
            aws_message.startswith(f"User: arn:aws:sts::{account}:assumed-role/")
            and denial in aws_message
            and aws_message.endswith("; Proxy: null)")
        ), f"expected the wrapped iam:PassRole denial for {role_arn!r}, got: {aws_message!r}"
    else:
        raise AssertionError(
            "expected a customer AutoScalingRoleArn on a table replica to be rejected with "
            "AccessDeniedException, the call succeeded instead"
        )

    after = _write_scaling_settings(12)()
    assert after is not None, "expected the replica's write-capacity settings unchanged at MaximumUnits=12"
    assert after["AutoScalingRoleArn"] == control_role_arn, (
        f"expected the service-linked role {control_role_arn!r} still bound, got "
        f"{after['AutoScalingRoleArn']!r} — the rejected call must not have taken effect"
    )


def _secondary_region(primary_region: str) -> str:
    """A region distinct from the primary, for a global table replica."""
    return "us-west-2" if primary_region != "us-west-2" else "us-east-1"


def _register_write_capacity_autoscaling(ctx: Any, aas: Any, table_name: str) -> None:
    resource_id = f"table/{table_name}"
    dimension = "dynamodb:table:WriteCapacityUnits"
    aas.register_scalable_target(
        ServiceNamespace="dynamodb",
        ResourceId=resource_id,
        ScalableDimension=dimension,
        MinCapacity=5,
        MaxCapacity=10,
        Tags={"sim2real": CHECK},
    )
    ctx.on_cleanup(lambda: _safe_deregister_scalable_target(aas, resource_id, dimension))
    policy_name = ctx.unique_name("sim2real-behav-tras-scale-")
    aas.put_scaling_policy(
        PolicyName=policy_name,
        ServiceNamespace="dynamodb",
        ResourceId=resource_id,
        ScalableDimension=dimension,
        PolicyType="TargetTrackingScaling",
        TargetTrackingScalingPolicyConfiguration={
            "TargetValue": 70.0,
            "ScaleInCooldown": 60,
            "ScaleOutCooldown": 60,
            "PredefinedMetricSpecification": {
                "PredefinedMetricType": "DynamoDBWriteCapacityUtilization"
            },
        },
    )
    ctx.on_cleanup(lambda: _safe_delete_scaling_policy(aas, policy_name, resource_id, dimension))


def _safe_deregister_scalable_target(aas: Any, resource_id: str, dimension: str) -> None:
    try:
        aas.deregister_scalable_target(
            ServiceNamespace="dynamodb", ResourceId=resource_id, ScalableDimension=dimension
        )
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ObjectNotFoundException":
            raise


def _safe_delete_scaling_policy(aas: Any, policy_name: str, resource_id: str, dimension: str) -> None:
    try:
        aas.delete_scaling_policy(
            PolicyName=policy_name,
            ServiceNamespace="dynamodb",
            ResourceId=resource_id,
            ScalableDimension=dimension,
        )
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ObjectNotFoundException":
            raise


def _create_replica_with_retry(
    ddb: Any, table_name: str, region: str, *, timeout_s: float = 90, interval_s: float = 5
) -> None:
    """Add a replica, retrying the transient "security token" AccessDeniedException that DynamoDB
    returns while cross-region replication setup settles right after the table turns ACTIVE."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            ddb.update_table(TableName=table_name, ReplicaUpdates=[{"Create": {"RegionName": region}}])
            return
        except Exception as exc:  # noqa: BLE001
            transient = _error_code_from_exc(exc) == "AccessDeniedException" and "security token" in str(
                exc
            ).lower()
            if not transient or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)


_CLEANUP_S = 900.0  # the suite's cleanup budget, shared by the check's teardowns
_TABLE_GONE = ("ResourceNotFoundException", "TableNotFoundException")
# DeleteTable's refusal while a replica the table seeded is still attached.
_SOURCE_REPLICA = (
    "Replica cannot be deleted because it has acted as a source region for new replica(s) being "
    "added to the table in the last 24 hours."
)
_NOT_A_REPLICA = "Update global table operation failed because one or more replicas were not part of the global table."


def _cleanup_deadline(teardown_deadline) -> float:
    return teardown_deadline.setdefault("t", time.monotonic() + _CLEANUP_S)


def _safe_remove_replica(ddb: Any, table_name: str, region: str, teardown_deadline) -> None:
    """Remove the replica once no replica update is in flight, then wait until DescribeTable no
    longer lists it; an in-use or not-yet-joined refusal retries every 2 s to the deadline."""
    deadline = _cleanup_deadline(teardown_deadline)
    while True:
        try:
            table = ddb.describe_table(TableName=table_name)["Table"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] in _TABLE_GONE:
                return
            raise
        replica = next((r for r in table.get("Replicas", []) if r["RegionName"] == region), None)
        if replica is None:
            return
        settled = table["TableStatus"] == "ACTIVE" and replica.get("ReplicaStatus") not in (
            "CREATING", "UPDATING", "DELETING"
        )
        if settled:
            try:
                ddb.update_table(TableName=table_name, ReplicaUpdates=[{"Delete": {"RegionName": region}}])
            except ClientError as exc:
                error = exc.response["Error"]
                if error["Code"] in _TABLE_GONE:
                    return
                busy = error["Code"] == "ResourceInUseException" or (
                    error["Code"] == "ValidationException" and error.get("Message", "").startswith(_NOT_A_REPLICA)
                )
                if not busy:
                    raise
        if time.monotonic() >= deadline:
            raise RuntimeError(f"replica {region} of {table_name} still listed after {_CLEANUP_S:.0f}s: {replica!r}")
        time.sleep(2)


def _create_autoscaling_role(ctx: Any, iam: Any) -> str:
    role_name = ctx.unique_name("sim2real-behav-tras-role-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "application-autoscaling.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: _safe_delete_role(iam, role_name))

    inline_policy_name = "dynamodb-autoscaling-permissions"
    permissions_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": [
                    "dynamodb:DescribeTable",
                    "dynamodb:UpdateTable",
                    "cloudwatch:PutMetricAlarm",
                    "cloudwatch:DescribeAlarms",
                    "cloudwatch:DeleteAlarms",
                ],
                "Resource": "*",
            }
        ],
    }
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName=inline_policy_name,
        PolicyDocument=json.dumps(permissions_policy),
    )
    ctx.on_cleanup(
        lambda: _safe_delete_role_policy(iam, role_name, inline_policy_name)
    )
    # No IAM propagation wait: the replica path can never pass this role (see run()).
    return role_arn


def _safe_delete_role_policy(iam: Any, role_name: str, policy_name: str) -> None:
    try:
        iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _safe_delete_role(iam: Any, role_name: str) -> None:
    try:
        iam.delete_role(RoleName=role_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _safe_delete_table(ddb: Any, table_name: str, teardown_deadline) -> None:
    """Delete the table; retry an in-use or still-attached-replica refusal, gone is done."""
    deadline = _cleanup_deadline(teardown_deadline)
    while True:
        try:
            ddb.delete_table(TableName=table_name)
            return
        except ClientError as exc:
            error = exc.response["Error"]
            if error["Code"] in _TABLE_GONE:
                return
            busy = error["Code"] == "ResourceInUseException" or (
                error["Code"] == "ValidationException" and error.get("Message") == _SOURCE_REPLICA
            )
            if not busy or time.monotonic() >= deadline:
                raise
        time.sleep(2)


def _error_code_from_exc(exc: Exception) -> str | None:
    response = getattr(exc, "response", None)
    if not response:
        return None
    return response.get("Error", {}).get("Code")


def _poll_until(
    probe: Callable[[], Any],
    predicate: Callable[[Any], bool],
    *,
    timeout_s: float,
    interval_s: float,
) -> Any:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s, last value: {last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
