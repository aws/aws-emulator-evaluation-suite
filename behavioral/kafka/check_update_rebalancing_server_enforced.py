"""update-rebalancing-server-enforced."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-rebalancing-server-enforced"
GROUP = 'overly-permissive'
SERVICES = ['kafka']

_NOT_FOUND = ("NotFoundException", "The requested resource doesn\u2019t exist.")
# MSK's answer to UpdateRebalancing on the check's own just-created cluster with CurrentVersion "1".
_INVALID_PARAMETERS = ("BadRequestException", "One or more of the parameters are not valid.")

def _err(fn):
    """Call fn(); return the botocore (Error.Code, Error.Message) of the ClientError it raises. An
    unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _account_id(ctx):
    if not hasattr(ctx, "_kafka_account_id"):
        ctx._kafka_account_id = ctx.client("sts").get_caller_identity()["Account"]
    return ctx._kafka_account_id


def _bogus_cluster_arn(ctx):
    """A well-formed MSK cluster ARN, in this account, that cannot exist."""
    return (
        f"arn:aws:kafka:{ctx.region}:{_account_id(ctx)}:cluster/"
        f"{ctx.unique_name('sim2real-behav-nonexistent-')}/"
        "00000000-0000-0000-0000-000000000000-1"
    )


def _sample_value(shape):
    enum = (shape.metadata or {}).get("enum") or getattr(shape, "enum", None)
    if shape.type_name == "string":
        return enum[0] if enum else "ENABLED"
    if shape.type_name == "boolean":
        return True
    if shape.type_name in ("integer", "long"):
        return 1
    if shape.type_name == "structure":
        return _minimal_payload(shape)
    if shape.type_name == "list":
        return [_sample_value(shape.member)]
    if shape.type_name == "map":
        return {}
    return "ENABLED"


def _minimal_payload(shape):
    """Smallest structurally-valid payload for a Smithy shape -- just enough to
    clear client-side validation so the request actually reaches the service."""
    out = {}
    required = set(shape.metadata.get("required", []) or [])
    members = getattr(shape, "members", {}) or {}
    for member_name in required or list(members)[:1]:
        member = members.get(member_name)
        if member is None:
            continue
        out[member_name] = _sample_value(member)
    return out


def _discover_subnets(ctx, minimum_subnets=2):
    """`minimum_subnets` subnets in distinct AZs of the run's network (ctx.network())."""
    net = ctx.network()
    zones = net.availability_zones
    if len(zones) < minimum_subnets:
        raise AssertionError(f"the run's network has subnets in {len(zones)} AZs, need {minimum_subnets}")
    return [net.subnets[az] for az in zones][:minimum_subnets]


def _create_real_cluster(ctx, msk):
    """This check's OWN real (still-CREATING) MSK cluster -- the positive control that
    proves UpdateRebalancing resolves a genuine ClusterArn differently from a ghost one,
    without waiting for ACTIVE before the assertions.

    A CREATING cluster can't be deleted (AWS refuses DeleteCluster until it leaves CREATING),
    so run() waits it out before the registered DeleteCluster teardown runs.
    """
    subnet_ids = _discover_subnets(ctx)
    name = ctx.unique_name("sim2real-behav-rebalance-")
    resp = msk.create_cluster_v2(
        ClusterName=name,
        Provisioned={
            "BrokerNodeGroupInfo": {
                "InstanceType": "kafka.m5.large",
                "ClientSubnets": subnet_ids,
            },
            "KafkaVersion": "3.9.x",
            "NumberOfBrokerNodes": len(subnet_ids),
        },
        Tags={"sim2real:managed": "true"},
    )
    arn = resp["ClusterArn"]
    ctx.on_cleanup(lambda: _delete_cluster_when_settled(msk, arn))
    return arn


def _delete_cluster_when_settled(msk, arn, timeout_s=2400.0, interval_s=30.0):
    """DeleteCluster refuses a cluster that is CREATING or UPDATING, so wait for ACTIVE or FAILED first,
    then wait until DescribeClusterV2 returns NotFoundException."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            state = msk.describe_cluster_v2(ClusterArn=arn)["ClusterInfo"]["State"]
            if state in ("ACTIVE", "FAILED"):
                msk.delete_cluster(ClusterArn=arn)
        except ClientError as e:
            if e.response["Error"]["Code"] == "NotFoundException":
                return
            raise
        if time.monotonic() >= deadline:
            raise AssertionError(f"cluster {arn} still {state} after {timeout_s:.0f}s; it was not deleted")
        time.sleep(interval_s)


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """UpdateRebalancing and ListClusterOperationsV2 return NotFoundException for an unknown cluster ARN,
    while the same calls against a real cluster do not, so the rejection is by identity."""
    msk = ctx.client("kafka")
    if not hasattr(msk, "update_rebalancing"):
        raise AssertionError("UpdateRebalancing absent from the installed botocore model")
    try:
        op_model = msk.meta.service_model.operation_model("UpdateRebalancing")
    except Exception as exc:  # noqa: BLE001
        raise AssertionError(f"UpdateRebalancing absent from the installed botocore model: {exc}") from exc
    members = getattr(op_model.input_shape, "members", {}) or {}
    if "Rebalancing" not in members:
        raise AssertionError("installed botocore model has no Rebalancing input member")

    payload = _minimal_payload(members["Rebalancing"])

    real_arn = _create_real_cluster(ctx, msk)

    try:
        # The real cluster resolves, so MSK refuses on the request's parameters, not on identity.
        real_err = _err(
            lambda: msk.update_rebalancing(
                ClusterArn=real_arn, CurrentVersion="1", Rebalancing=payload
            )
        )
        assert real_err == _INVALID_PARAMETERS, (
            f"UpdateRebalancing on this check's OWN cluster ({real_arn}): expected "
            f"{_INVALID_PARAMETERS!r}, got {real_err!r}"
        )

        real_ops = msk.list_cluster_operations_v2(ClusterArn=real_arn)
        assert "ClusterOperationInfoList" in real_ops, real_ops

        ghost = _bogus_cluster_arn(ctx)

        err = _err(
            lambda: msk.update_rebalancing(
                ClusterArn=ghost, CurrentVersion="1", Rebalancing=payload
            )
        )
        assert err == _NOT_FOUND, f"expected {_NOT_FOUND!r}, got {err!r}"

        listed = _err(lambda: msk.list_cluster_operations_v2(ClusterArn=ghost))
        assert listed == _NOT_FOUND, f"ListClusterOperationsV2: expected {_NOT_FOUND!r}, got {listed!r}"
    finally:
        _wait_until_deletable(msk, real_arn)


def _wait_until_deletable(msk, arn, *, timeout_s=3600, interval_s=30.0):
    """Poll until the cluster leaves CREATING, so the registered DeleteCluster teardown is accepted
    (AWS refuses DeleteCluster while a cluster is CREATING). Raises on timeout."""
    deadline = time.monotonic() + timeout_s
    state = None
    while time.monotonic() < deadline:
        state = msk.describe_cluster_v2(ClusterArn=arn)["ClusterInfo"]["State"]
        if state != "CREATING":
            return state
        time.sleep(interval_s)
    raise AssertionError(f"cluster {arn} still {state!r} after {timeout_s}s; DeleteCluster would be refused")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
