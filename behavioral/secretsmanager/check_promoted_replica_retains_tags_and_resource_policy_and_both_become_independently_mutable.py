"""promoted-replica-retains-tags-and-resource-policy-and-both-become-independently-mutable."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "promoted-replica-retains-tags-and-resource-policy-and-both-become-independently-mutable"
GROUP = "replication"
SERVICES = ["secretsmanager"]

# Cross-region replication needs two distinct, real regions; these are fixed so any residue lands
# where this check's cleanup deletes it.
_REPLICA_REGION_PRIMARY = "us-east-1"
_REPLICA_REGION_FALLBACK = "us-west-2"


@tags(
    "axis:happy-path",
    "cap:c2",
    "concern:representation",
    "plane:control",
)
def run(ctx) -> None:
    """A replica promoted by StopReplicationToReplica keeps its tag and resource policy.

    The promoted secret is then independently mutable: TagResource and DeleteResourcePolicy against
    it succeed and leave the primary's tags and policy untouched.
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

    name = ctx.unique_name("sim2real-behav-promopol-")
    created = sm.create_secret(
        Name=name,
        SecretString="promopol-v1",
        Tags=[{"Key": "sim2real", "Value": CHECK}, {"Key": "T1", "Value": "v1"}],
    )
    primary_arn = created["ARN"]
    ctx.on_cleanup(lambda: _reap_secret(sm, primary_arn))
    # Registered before the first replicate call so it is armed even on a mid-way failure; LIFO
    # means this detaches/reaps the (possibly promoted) replica BEFORE the primary reap above runs.
    ctx.on_cleanup(lambda: _detach_and_reap_replica(sm, sm_replica, primary_arn, name, replica_region))

    policy_v1 = _policy(primary_arn, "secretsmanager:GetSecretValue")
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
        f"replication to {replica_region} must reach InSync before promotion can be graded; "
        f"got {status!r}"
    )

    # Wait for both the tag and the policy to propagate before promoting, so the promotion's
    # "retains" claim below is measured against a replica that genuinely had them.
    _poll_until(
        lambda: _try_describe(sm_replica, name),
        lambda d: d is not None and {"Key": "T1", "Value": "v1"} in d.get("Tags", []),
        timeout_s=120.0,
        interval_s=3.0,
        description="the primary's tag to propagate to the replica before promotion",
    )
    _poll_until(
        lambda: _try_get_policy(sm_replica, name),
        lambda p: p is not None,
        timeout_s=120.0,
        interval_s=3.0,
        description="the primary's resource policy to propagate to the replica before promotion",
    )

    # --- promote --------------------------------------------------------------------------------
    sm_replica.stop_replication_to_replica(SecretId=name)
    _poll_until(
        lambda: sm.describe_secret(SecretId=primary_arn),
        lambda d: replica_region not in [r["Region"] for r in d.get("ReplicationStatus", [])],
        timeout_s=180.0,
        interval_s=3.0,
        description=f"the primary to drop {replica_region} after StopReplicationToReplica",
    )

    # --- retained: the promoted secret keeps the tag and policy it held at promotion ------------
    promoted = sm_replica.describe_secret(SecretId=name)
    assert {"Key": "T1", "Value": "v1"} in promoted.get("Tags", []), (
        f"the promoted secret must retain the tag it held at the moment of promotion; got "
        f"{promoted.get('Tags')!r}"
    )
    promoted_policy = sm_replica.get_resource_policy(SecretId=name).get("ResourcePolicy")
    assert promoted_policy is not None, (
        "the promoted secret must retain the resource policy it held at the moment of promotion; "
        "GetResourcePolicy returned none"
    )
    assert json.loads(promoted_policy)["Statement"][0] == policy_v1["Statement"][0], (
        f"the promoted secret's resource policy must match what it held just before promotion: "
        f"expected {policy_v1['Statement'][0]!r}, got {json.loads(promoted_policy)['Statement'][0]!r}"
    )

    # --- independent: mutations against the promoted secret succeed ------------------------------
    # A read immediately after either call can still return the pre-mutation value, so each is a
    # bounded poll rather than a one-shot read.
    sm_replica.tag_resource(SecretId=name, Tags=[{"Key": "T2", "Value": "v2"}])
    after_tag = _poll_until(
        lambda: sm_replica.describe_secret(SecretId=name),
        lambda d: {"Key": "T2", "Value": "v2"} in d.get("Tags", []),
        timeout_s=60.0,
        interval_s=2.0,
        description="TagResource against the promoted secret to become visible",
    )
    assert {"Key": "T2", "Value": "v2"} in after_tag.get("Tags", []), (
        f"TagResource against the promoted secret must succeed now that it is independent; got "
        f"{after_tag.get('Tags')!r}"
    )

    sm_replica.delete_resource_policy(SecretId=name)
    after_delete = _poll_until(
        lambda: sm_replica.get_resource_policy(SecretId=name),
        lambda p: not p.get("ResourcePolicy"),
        timeout_s=60.0,
        interval_s=2.0,
        description="DeleteResourcePolicy against the promoted secret to become visible",
    )
    assert not after_delete.get("ResourcePolicy"), (
        f"DeleteResourcePolicy against the promoted secret must succeed now that it is independent; "
        f"got ResourcePolicy={after_delete.get('ResourcePolicy')!r}"
    )

    # --- the primary is untouched by mutations on the (former) replica --------------------------
    primary_after = sm.describe_secret(SecretId=primary_arn)
    assert {"Key": "T2", "Value": "v2"} not in primary_after.get("Tags", []), (
        f"a tag added on the promoted secret must not appear on the primary; got "
        f"{primary_after.get('Tags')!r}"
    )
    primary_policy_after = sm.get_resource_policy(SecretId=primary_arn).get("ResourcePolicy")
    assert primary_policy_after is not None, (
        "deleting the promoted secret's resource policy must not delete the primary's; "
        "GetResourcePolicy on the primary returned none"
    )
    assert json.loads(primary_policy_after)["Statement"][0] == policy_v1["Statement"][0], (
        f"the primary's resource policy must be unaffected by the promoted secret's "
        f"DeleteResourcePolicy: expected {policy_v1['Statement'][0]!r}, got "
        f"{json.loads(primary_policy_after)['Statement'][0]!r}"
    )


# ===== helpers (self-contained) =====


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
    region -- a promoted standalone secret or an unpromoted attached one. Both halves matter on the
    failure path too: the primary refuses deletion while a replica exists, and a plain delete
    is region-scoped, so a promoted secret in the replica region is invisible to it.
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
        f"ex-replica/promoted secret {name} in {replica_region} could not be force-deleted; "
        f"it bills $0.40/month and NO region-scoped cleanup will find it"
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
