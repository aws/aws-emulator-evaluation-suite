"""replica-refuses-tag-and-resource-policy-mutations-while-reads-propagate."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "replica-refuses-tag-and-resource-policy-mutations-while-reads-propagate"
GROUP = "replication"
SERVICES = ["secretsmanager"]

_REPLICA_REGION_PRIMARY = "us-east-1"
_REPLICA_REGION_FALLBACK = "us-west-2"


@tags(
    "axis:rejection",
    "cap:c2",
    "concern:negative-classes",
    "plane:control",
)
def run(ctx) -> None:
    """An attached replica refuses TagResource, UntagResource, PutResourcePolicy and
    DeleteResourcePolicy with InvalidParameterException while still serving reads and validation,
    and the same mutations made on the primary propagate to it.
    """
    sm = ctx.client("secretsmanager")
    replica_region = (
        _REPLICA_REGION_FALLBACK if ctx.region == _REPLICA_REGION_PRIMARY
        else _REPLICA_REGION_PRIMARY
    )
    assert replica_region != ctx.region, (
        f"the replica region must differ from the primary's; both resolved to {ctx.region!r}"
    )
    sm_replica = ctx.client("secretsmanager", region=replica_region)

    name = ctx.unique_name("sim2real-behav-replicapol-")
    created = sm.create_secret(
        Name=name,
        SecretString="replicapol-v1",
        Tags=[{"Key": "sim2real", "Value": CHECK}, {"Key": "T1", "Value": "v1"}],
    )
    primary_arn = created["ARN"]
    ctx.on_cleanup(lambda: _reap_secret(sm, primary_arn))
    # Cleanup is LIFO, so this runs before the primary reap: a primary with a live replica refuses
    # deletion.
    ctx.on_cleanup(lambda: _detach_and_reap_replica(sm, sm_replica, primary_arn, name, replica_region))

    policy_v1 = _policy(primary_arn, "secretsmanager:GetSecretValue")
    policy_v2 = _policy(primary_arn, "secretsmanager:DescribeSecret")

    sm.put_resource_policy(SecretId=primary_arn, ResourcePolicy=json.dumps(policy_v1))

    sm.replicate_secret_to_regions(SecretId=primary_arn, AddReplicaRegions=[{"Region": replica_region}])
    _poll_until(
        lambda: _replication_status(sm, primary_arn, replica_region),
        lambda st: st is not None and st.get("Status") in ("InSync", "Failed"),
        timeout_s=180.0,
        interval_s=3.0,
        description=f"the {replica_region} replica to reach a terminal replication status",
    )
    status = _replication_status(sm, primary_arn, replica_region)
    assert status.get("Status") == "InSync", (
        f"replication to {replica_region} must reach InSync before the constraint can be graded; "
        f"got {status!r}"
    )

    replica_tags = _poll_until(
        lambda: _try_describe(sm_replica, name),
        lambda d: d is not None and {"Key": "T1", "Value": "v1"} in d.get("Tags", []),
        timeout_s=120.0,
        interval_s=3.0,
        description=f"the primary's tag to propagate to the {replica_region} replica",
    )["Tags"]
    assert {"Key": "T1", "Value": "v1"} in replica_tags, (
        f"the replica must carry the primary's tags at attach time; got {replica_tags!r}"
    )
    replica_policy = _poll_until(
        lambda: _try_get_policy(sm_replica, name),
        lambda p: p is not None,
        timeout_s=120.0,
        interval_s=3.0,
        description=f"the primary's resource policy to propagate to the {replica_region} replica",
    )
    assert json.loads(replica_policy)["Statement"][0] == policy_v1["Statement"][0], (
        f"the replica's resource policy must match the primary's: expected "
        f"{policy_v1['Statement'][0]!r}, got {json.loads(replica_policy)['Statement'][0]!r}"
    )

    mutations = {
        "TagResource": lambda: sm_replica.tag_resource(SecretId=name, Tags=[{"Key": "T2", "Value": "v2"}]),
        "UntagResource": lambda: sm_replica.untag_resource(SecretId=name, TagKeys=["T1"]),
        "PutResourcePolicy": lambda: sm_replica.put_resource_policy(
            SecretId=name, ResourcePolicy=json.dumps(policy_v2)
        ),
        "DeleteResourcePolicy": lambda: sm_replica.delete_resource_policy(SecretId=name),
    }
    expected_message = "Operation not permitted on a replica secret. Call must be made in primary secret's region."
    for op_name, fn in mutations.items():
        code, message = _error(fn)
        assert code == "InvalidParameterException", (
            f"{op_name} against an attached replica must be refused with InvalidParameterException; "
            f"got {code!r} ({message!r})"
        )
        assert message == expected_message, (
            f"{op_name} against an attached replica must carry the exact replica-refusal message; "
            f"expected {expected_message!r}, got {message!r}"
        )

    unchanged = sm_replica.describe_secret(SecretId=name)
    assert {"Key": "T1", "Value": "v1"} in unchanged.get("Tags", []), (
        f"the refused UntagResource must not have removed the tag; got {unchanged.get('Tags')!r}"
    )
    assert {"Key": "T2", "Value": "v2"} not in unchanged.get("Tags", []), (
        f"the refused TagResource must not have added a tag; got {unchanged.get('Tags')!r}"
    )
    unchanged_policy = sm_replica.get_resource_policy(SecretId=name)["ResourcePolicy"]
    assert json.loads(unchanged_policy)["Statement"][0] == policy_v1["Statement"][0], (
        f"the refused PutResourcePolicy/DeleteResourcePolicy must not have changed the replica's "
        f"policy; expected {policy_v1['Statement'][0]!r}, got "
        f"{json.loads(unchanged_policy)['Statement'][0]!r}"
    )

    # ValidateResourcePolicy mutates nothing, so a replica still serves it.
    validation = sm_replica.validate_resource_policy(SecretId=name, ResourcePolicy=json.dumps(policy_v2))
    assert validation["PolicyValidationPassed"] is True, (
        f"ValidateResourcePolicy against a replica must still run (it mutates nothing); got "
        f"{validation!r}"
    )

    # Twin control: the identical mutations against the primary succeed and propagate.
    sm.tag_resource(SecretId=primary_arn, Tags=[{"Key": "T2", "Value": "v2"}])
    sm.put_resource_policy(SecretId=primary_arn, ResourcePolicy=json.dumps(policy_v2))
    propagated = _poll_until(
        lambda: _try_describe(sm_replica, name),
        lambda d: d is not None and {"Key": "T2", "Value": "v2"} in d.get("Tags", []),
        timeout_s=120.0,
        interval_s=3.0,
        description="the primary's new tag to propagate to the replica",
    )
    assert {"Key": "T2", "Value": "v2"} in propagated.get("Tags", []), (
        f"a tag added on the primary must propagate to the replica; got {propagated.get('Tags')!r}"
    )
    propagated_policy = _poll_until(
        lambda: _try_get_policy(sm_replica, name),
        lambda p: p is not None and json.loads(p)["Statement"][0] == policy_v2["Statement"][0],
        timeout_s=120.0,
        interval_s=3.0,
        description="the primary's updated resource policy to propagate to the replica",
    )
    assert json.loads(propagated_policy)["Statement"][0] == policy_v2["Statement"][0], (
        f"a resource policy change on the primary must propagate to the replica: expected "
        f"{policy_v2['Statement'][0]!r}, got {json.loads(propagated_policy)['Statement'][0]!r}"
    )


def _policy(arn: str, action: str) -> dict:
    account_id = arn.split(":")[4]
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                "Action": action,
                "Resource": arn,
            }
        ],
    }


def _error(fn):
    """Call fn(); return the botocore (Error.Code, Error.Message); an unexpected success raises."""
    try:
        fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError("the call was expected to fail but SUCCEEDED")


def _poll_until(probe, predicate, *, timeout_s, interval_s, description):
    deadline = time.monotonic() + timeout_s
    last = probe()
    while not predicate(last):
        if time.monotonic() >= deadline:
            raise AssertionError(f"waited {timeout_s}s for {description}; last observation was {last!r}")
        time.sleep(interval_s)
        last = probe()
    return last


def _replication_status(sm, secret_id: str, region: str):
    for row in sm.describe_secret(SecretId=secret_id).get("ReplicationStatus", []):
        if row["Region"] == region:
            return row
    return None


def _try_describe(client, secret_id: str):
    try:
        return client.describe_secret(SecretId=secret_id)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == "ResourceNotFoundException":
            return None
        raise


def _try_get_policy(client, secret_id: str):
    try:
        return client.get_resource_policy(SecretId=secret_id).get("ResourcePolicy")
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == "ResourceNotFoundException":
            return None
        raise


def _detach_and_reap_replica(sm, sm_replica, primary_arn: str, name: str, replica_region: str) -> None:
    """Break any surviving replication link, then force-delete whatever is left in the replica
    region; the primary refuses deletion while a replica exists.
    """
    try:
        sm.remove_regions_from_replication(SecretId=primary_arn, RemoveReplicaRegions=[replica_region])
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code")
        if code not in ("ResourceNotFoundException", "InvalidParameterException", "InvalidRequestException"):
            raise RuntimeError(f"remove_regions_from_replication({primary_arn}) failed with {code}: {exc}") from exc
    deadline = time.monotonic() + 120.0
    while time.monotonic() < deadline:
        try:
            sm_replica.delete_secret(SecretId=name, ForceDeleteWithoutRecovery=True)
            return
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "ResourceNotFoundException":
                return
            time.sleep(3.0)
    raise RuntimeError(
        f"ex-replica secret {name} in {replica_region} could not be force-deleted; it bills "
        f"$0.40/month and NO region-scoped cleanup will find it"
    )


def _reap_secret(sm, secret_id: str, timeout_s: float = 120.0) -> None:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            sm.delete_secret(SecretId=secret_id, ForceDeleteWithoutRecovery=True)
            break
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "ResourceNotFoundException":
                return
            # A secret with a live replica refuses deletion; the detach above is asynchronous.
            time.sleep(3.0)
            continue
    while time.monotonic() < deadline:
        try:
            sm.describe_secret(SecretId=secret_id)
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "ResourceNotFoundException":
                return
        time.sleep(2.0)
    raise RuntimeError(f"secret {secret_id} still present {timeout_s}s after ForceDeleteWithoutRecovery")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
