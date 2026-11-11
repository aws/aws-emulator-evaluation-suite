"""replicator-delete-transition."""

from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError
from behavioral_harness import tags

CHECK = "replicator-delete-transition"
GROUP = 'cluster-lifecycle'
SERVICES = ['kafka']

_DEFAULT_KAFKA_VERSION = "3.9.x"
_PROVISIONED_INSTANCE_TYPE = "kafka.m5.large"


def _err(fn):
    """Call fn(); return the (code, message) of the ClientError it raises. A success raises."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _gone_ok(fn, gone_code):
    """Call fn(); a ClientError with `gone_code` means the resource is already gone, anything else raises."""
    try:
        fn()
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != gone_code:
            raise


def _poll_until(probe, predicate, *, timeout_s=60, interval_s=1.0, description="condition", ctx=None):
    """Poll probe() until predicate(result) is truthy; return the final result."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    if ctx is not None and _budget_spent(ctx):
        raise TimeoutError(f"{description}: the run budget ended first; not graded")
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _account_id(ctx):
    if not hasattr(ctx, "_kafka_account_id"):
        ctx._kafka_account_id = ctx.client("sts").get_caller_identity()["Account"]
    return ctx._kafka_account_id


def _discover_network(ctx, minimum_subnets=2):
    """The run's shared network: its VPC, up to three subnets in distinct AZs, and the default
    security group."""
    net = ctx.network()
    zones = net.availability_zones
    assert len(zones) >= minimum_subnets, (
        f"the shared network has subnets in {len(zones)} availability zones, need {minimum_subnets}"
    )
    return net.vpc_id, [net.subnets[az] for az in zones][:3], net.security_group_id


def _create_cluster_network(ctx, num_subnets=2):
    """The shared network, memoized on ctx."""
    if not hasattr(ctx, "_kafka_net"):
        ctx._kafka_net = _discover_network(ctx, minimum_subnets=2)
    vpc_id, subnet_ids, sg_id = ctx._kafka_net
    if num_subnets > len(subnet_ids):
        raise AssertionError(f"discovered network only has {len(subnet_ids)} subnets, need {num_subnets}")
    return vpc_id, subnet_ids[:num_subnets], sg_id


def _provisioned_body(subnet_ids, sg_id, num_brokers=2, kafka_version=_DEFAULT_KAFKA_VERSION,
                      instance_type=_PROVISIONED_INSTANCE_TYPE, volume_size=10):
    broker_info = {
        "InstanceType": instance_type,
        "ClientSubnets": subnet_ids,
        "StorageInfo": {"EbsStorageInfo": {"VolumeSize": volume_size}},
    }
    if sg_id:
        broker_info["SecurityGroups"] = [sg_id]
    return {
        "BrokerNodeGroupInfo": broker_info,
        "KafkaVersion": kafka_version,
        "NumberOfBrokerNodes": num_brokers,
    }


def _create_basic_cluster(ctx, msk, num_brokers=2, num_subnets=2,
                          kafka_version=_DEFAULT_KAFKA_VERSION,
                          name_prefix="cluster-", tags=None):
    """Start a PROVISIONED cluster and register its teardown; return (arn, name, subnet_ids, sg_id).

    MSK requires NumberOfBrokerNodes to be a multiple of the client-subnet count, hence num_subnets."""
    name = ctx.unique_name("sim2real-behav-" + name_prefix)
    _, subnet_ids, sg_id = _create_cluster_network(ctx, num_subnets=num_subnets)
    prov = _provisioned_body(subnet_ids, sg_id, num_brokers=num_brokers, kafka_version=kafka_version)
    # MSK Replicator reaches both clusters with IAM access control (port 9098) and nothing else,
    # so a cluster without SASL/IAM can never host a replicator. Unauthenticated access stays off,
    # which is what specifying ClientAuthentication at all does.
    prov["ClientAuthentication"] = {"Sasl": {"Iam": {"Enabled": True}}}
    kwargs = {
        "ClusterName": name,
        "Provisioned": prov,
        "Tags": {"sim2real:managed": "true", **(tags or {})},
    }
    try:
        resp = msk.create_cluster_v2(**kwargs)
    except Exception as exc:  # noqa: BLE001
        code = getattr(exc, "response", {}).get("Error", {}).get("Code", "")
        raise AssertionError(
            f"could not create an MSK cluster for this check ({code}: {exc}); "
            f"network used: vpc subnets={subnet_ids} sg={sg_id}"
        ) from exc
    arn = resp["ClusterArn"]
    ctx.on_cleanup(lambda: _delete_cluster_when_settled(ctx, msk, arn))
    return arn, name, subnet_ids, sg_id


# One deadline shared by all of the check's teardowns, inside the suite's 1800 s cleanup budget.
_TEARDOWN_S = 1740.0
_DEADLINES: dict = {}


def _deadline(ctx) -> float:
    """The run's teardown deadline, started by its first teardown."""
    held = _DEADLINES.get(id(ctx))
    if held is None or held[0] is not ctx:
        held = _DEADLINES[id(ctx)] = (ctx, time.monotonic() + _TEARDOWN_S)
    return held[1]


def _delete_cluster_when_settled(ctx, msk, arn, interval_s=2.0):
    """DeleteCluster refuses a cluster that is CREATING or UPDATING (BadRequestException), so wait for
    ACTIVE or FAILED first; then poll until DescribeClusterV2 answers NotFoundException, all to the
    shared teardown deadline."""
    deadline = _deadline(ctx)
    state = None
    while True:
        try:
            state = msk.describe_cluster_v2(ClusterArn=arn)["ClusterInfo"]["State"]
            if state in ("ACTIVE", "FAILED"):
                msk.delete_cluster(ClusterArn=arn)
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code == "NotFoundException":
                return
            if code != "BadRequestException":
                raise
        if time.monotonic() >= deadline:
            raise AssertionError(f"cluster {arn} still {state} at the teardown deadline")
        time.sleep(interval_s)


def _wait_cluster_active(ctx, msk, arn, timeout_s=2700, interval_s=1):
    """Poll DescribeCluster (v1) until the cluster settles; raise unless it is ACTIVE."""
    info = _poll_until(
        lambda: msk.describe_cluster(ClusterArn=arn)["ClusterInfo"],
        lambda i: i.get("State") in ("ACTIVE", "FAILED"),
        timeout_s=_budget_s(ctx, timeout_s),
        interval_s=interval_s,
        description=f"cluster {arn} to settle",
        ctx=ctx,
    )
    if info.get("State") != "ACTIVE":
        raise AssertionError(f"cluster reached {info.get('State')} instead of ACTIVE")
    return info


#: The managed policy AWS documents for a replicator service-execution role: read the source,
#: write the target. Anything less and the replicator creates, then settles FAILED. The
#: ``/service-role/`` path is part of the ARN -- the bare ``iam::aws:policy/<name>`` form is a
#: different, nonexistent policy and AttachRolePolicy answers NoSuchEntity for it.
_SER_MANAGED_POLICY = "arn:aws:iam::aws:policy/service-role/AWSMSKReplicatorExecutionRole"


def _replicator_role_arn(ctx):
    """ARN of the service-execution role MSK Replicator assumes to read source / write target.

    Created by the check (CreateReplicator rejects a nonexistent role), memoized on ctx, and made
    before the clusters so their provisioning time covers IAM propagation.
    """
    if getattr(ctx, "_kafka_ser_arn", None):
        return ctx._kafka_ser_arn
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-behav-msk-ser-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "kafka.amazonaws.com"},
                "Action": "sts:AssumeRole",
                "Condition": {"StringEquals": {"aws:SourceAccount": _account_id(ctx)}},
            }
        ],
    }
    arn = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Description="sim2real behavioral MSK Replicator service execution role",
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )["Role"]["Arn"]

    def _drop_role(_n=name):
        # Detach first: DeleteRole is rejected while a managed policy is still attached, and a
        # role left behind persists. Registered before any cluster or replicator teardown so LIFO
        # runs it LAST -- deleting the role while the replicator still holds it would fail.
        _gone_ok(lambda: iam.detach_role_policy(RoleName=_n, PolicyArn=_SER_MANAGED_POLICY), "NoSuchEntity")
        _gone_ok(lambda: iam.delete_role(RoleName=_n), "NoSuchEntity")

    ctx.on_cleanup(_drop_role)
    iam.attach_role_policy(RoleName=name, PolicyArn=_SER_MANAGED_POLICY)
    ctx._kafka_ser_arn = arn
    return arn


def _replication_info(source_arn, target_arn):
    return {
        "SourceKafkaClusterArn": source_arn,
        "TargetKafkaClusterArn": target_arn,
        # REQUIRED by the API model (ReplicationInfo.required); omitting it fails botocore's
        # client-side parameter validation.
        "TargetCompressionType": "NONE",
        "TopicReplication": {
            "TopicsToReplicate": [".*"],
            "CopyTopicConfigurations": True,
            "CopyAccessControlListsForTopics": False,
            "DetectAndCopyNewTopics": False,
        },
        "ConsumerGroupReplication": {
            "ConsumerGroupsToReplicate": [".*"],
            "DetectAndCopyNewConsumerGroups": False,
            "SynchroniseConsumerGroupOffsets": False,
        },
    }


def _wait_replicator_state(ctx, msk, arn, states, timeout_s=2700, interval_s=1):
    info = _poll_until(
        lambda: msk.describe_replicator(ReplicatorArn=arn),
        lambda i: i.get("ReplicatorState") in states,
        timeout_s=_budget_s(ctx, timeout_s),
        interval_s=interval_s,
        description=f"replicator {arn} to reach {states}",
        ctx=ctx,
    )
    return info


def _active_cluster(ctx, msk, name_prefix, num_brokers=2):
    arn, _name, _subnets, _sg = _create_basic_cluster(ctx, msk, num_brokers=num_brokers, name_prefix=name_prefix)
    _wait_cluster_active(ctx, msk, arn)
    return arn


#: MSK Replicator refuses a cluster with fewer than 3 brokers: with 2 the
#: replicator is ACCEPTED and then settles FAILED with
#: InvalidInput.InvalidKafkaCluster "The specified Amazon MSK Cluster has less than 3 brokers".
#: MSK separately requires NumberOfBrokerNodes to be a multiple of the client-subnet count, so the
#: broker count and the AZ spread have to move together.
_REPLICATOR_MIN_BROKERS = 3


def _two_active_clusters(ctx, msk, source_prefix, target_prefix,
                         num_brokers=_REPLICATOR_MIN_BROKERS, num_subnets=_REPLICATOR_MIN_BROKERS):
    """Both clusters ACTIVE, provisioned concurrently so the ~20 min builds overlap."""
    source_arn, _sn, _ss, _sg = _create_basic_cluster(
        ctx, msk, num_brokers=num_brokers, num_subnets=num_subnets, name_prefix=source_prefix
    )
    target_arn, _tn, _ts, _tg = _create_basic_cluster(
        ctx, msk, num_brokers=num_brokers, num_subnets=num_subnets, name_prefix=target_prefix
    )
    _wait_cluster_active(ctx, msk, source_arn)
    _wait_cluster_active(ctx, msk, target_arn)
    return source_arn, target_arn


def _kafka_cluster_entry(msk, cluster_arn):
    """One CreateReplicator KafkaClusters entry, networked like the cluster itself.

    Same-region replication needs security groups on BOTH clusters: the replicator's groups must
    allow egress to the cluster's groups on 9098 (IAM access control) and the cluster's groups must
    accept it. Reusing the cluster's own group satisfies that through the VPC default group's
    self-referencing rule.
    """
    bng = msk.describe_cluster(ClusterArn=cluster_arn)["ClusterInfo"]["BrokerNodeGroupInfo"]
    vpc_config = {"SubnetIds": bng["ClientSubnets"]}
    if bng.get("SecurityGroups"):
        vpc_config["SecurityGroupIds"] = bng["SecurityGroups"]
    return {"AmazonMskCluster": {"MskClusterArn": cluster_arn}, "VpcConfig": vpc_config}


def _create_replicator(ctx, msk, source_arn, target_arn, name_prefix):
    name = ctx.unique_name(name_prefix)
    resp = msk.create_replicator(
        ReplicatorName=name,
        ServiceExecutionRoleArn=_replicator_role_arn(ctx),
        KafkaClusters=[
            _kafka_cluster_entry(msk, source_arn),
            _kafka_cluster_entry(msk, target_arn),
        ],
        ReplicationInfoList=[_replication_info(source_arn, target_arn)],
        Tags={"sim2real:managed": "true"},
    )
    arn = resp["ReplicatorArn"]

    def _drop(_a=arn):
        # DeleteReplicator is rejected while the replicator is still CREATING -- exactly its
        # state when _wait_replicator_state times out and aborts the check -- so retry until
        # it either lands or is gone. NotFound-tolerant because a check may delete the replicator
        # as part of the behavior under test.
        #
        # Then WAIT for it to be GONE, not merely accepted: DeleteReplicator only moves the
        # replicator to DELETING, and a replicator holds its source and target clusters, so the
        # DeleteCluster teardowns that run after this one (cleanups are LIFO) are refused while it
        # still exists. Returning at "delete accepted" would leave both clusters behind.
        deadline = _deadline(ctx)
        while True:
            try:
                msk.delete_replicator(ReplicatorArn=_a)
                break
            except ClientError as exc:
                code = exc.response.get("Error", {}).get("Code")
                if code == "NotFoundException":
                    return
                if code != "BadRequestException" or time.monotonic() >= deadline:
                    raise
            time.sleep(2)
        while time.monotonic() < deadline:
            try:
                msk.describe_replicator(ReplicatorArn=_a)
            except ClientError as exc:
                if exc.response.get("Error", {}).get("Code") == "NotFoundException":
                    return
                raise
            time.sleep(2)
        raise AssertionError(f"replicator {_a} still exists at the teardown deadline")

    ctx.on_cleanup(_drop)
    return arn, name


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeleteReplicator moves a RUNNING replicator through DELETING to removed; DescribeReplicator
    then 404s and a second delete fails with NotFoundException and its exact message."""
    msk = ctx.client("kafka")
    # Before the clusters: a role rejected at CreateReplicator would waste both provisions, and
    # the wait below doubles as IAM propagation time.
    _replicator_role_arn(ctx)
    source_arn, target_arn = _two_active_clusters(ctx, msk, "repl-del-src-", "repl-del-tgt-")

    replicator_arn, _name = _create_replicator(ctx, msk, source_arn, target_arn, "sim2real-behav-replicator-del-")
    info = _wait_replicator_state(ctx, msk, replicator_arn, ("RUNNING", "FAILED"))
    # FAILED is accepted as terminal only so the wait cannot hang; the RUNNING -> DELETING
    # transition under test is only exercised from RUNNING, so pin it here. StateInfo carries WHY
    # it failed.
    assert info["ReplicatorState"] == "RUNNING", (
        f"replicator did not reach RUNNING, got {info['ReplicatorState']}: {info.get('StateInfo')}"
    )

    # DeleteReplicator answers with the state it moved the replicator to, so a short DELETING
    # phase is observed even when the first describe lands after removal.
    deleted = msk.delete_replicator(ReplicatorArn=replicator_arn)

    seen_states = [deleted.get("ReplicatorState")]

    def _probe():
        try:
            state = msk.describe_replicator(ReplicatorArn=replicator_arn)["ReplicatorState"]
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code == "NotFoundException":
                return "NotFoundException"
            raise
        seen_states.append(state)
        return state

    # _poll_until only ever returns once its predicate holds (otherwise it raises), so asserting
    # the return value against that same predicate would be tautological -- the raise-on-timeout
    # IS the failure signal for "never went away".
    _poll_until(
        _probe,
        lambda state: state == "NotFoundException",
        timeout_s=_budget_s(ctx, 600),
        interval_s=1,
        description="replicator to be deleted",
        ctx=ctx,
    )
    # The check's name is the TRANSITION, not merely before/after: without this a target
    # that jumps straight from RUNNING to gone (skipping DELETING outright) would pass
    # identically to one that actually transitions through it.
    assert "DELETING" in seen_states, (
        f"replicator vanished without ever reporting DELETING; observed states: {seen_states}"
    )

    # The dead id stays dead: a second delete on the same ARN must fail the same way,
    # not silently succeed against nothing.
    redelete_code, redelete_message = _err(lambda: msk.delete_replicator(ReplicatorArn=replicator_arn))
    assert redelete_code == "NotFoundException", (
        f"delete on an already-deleted replicator: expected NotFoundException, got {redelete_code!r}"
    )
    assert redelete_message == "Invalid parameter replicatorArn: The requested resource doesn\u2019t exist.", (
        f"delete on an already-deleted replicator: message {redelete_message!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
