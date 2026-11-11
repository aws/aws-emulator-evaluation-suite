"""serverless-bootstrap-broker-endpoint-set."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "serverless-bootstrap-broker-endpoint-set"
GROUP = 'data-plane'
SERVICES = ['kafka']

# GetBootstrapBrokersResponse models 14 mutually-exclusive endpoint strings. A cluster
# must advertise exactly the ones its ClientAuthentication/EncryptionInfo/ConnectivityInfo
# imply and no others. For MSK Serverless the auth surface is fixed: SASL/IAM only, in-VPC
# only, TLS-only in transit -> exactly BootstrapBrokerStringSaslIam.
_ALL_ENDPOINT_KEYS = (
    "BootstrapBrokerString",
    "BootstrapBrokerStringTls",
    "BootstrapBrokerStringSaslScram",
    "BootstrapBrokerStringSaslIam",
    "BootstrapBrokerStringPublicTls",
    "BootstrapBrokerStringPublicSaslScram",
    "BootstrapBrokerStringPublicSaslIam",
    "BootstrapBrokerStringVpcConnectivityTls",
    "BootstrapBrokerStringVpcConnectivitySaslScram",
    "BootstrapBrokerStringVpcConnectivitySaslIam",
    "BootstrapBrokerStringIpv6",
    "BootstrapBrokerStringTlsIpv6",
    "BootstrapBrokerStringSaslScramIpv6",
    "BootstrapBrokerStringSaslIamIpv6",
)
_SERVERLESS_EXPECTED = "BootstrapBrokerStringSaslIam"
_SASL_IAM_PORT = 9098

# A serverless cluster has no broker fleet to provision, so it is the cheapest MSK shape
# that can legitimately reach ACTIVE. It is still minutes, not seconds.
_ACTIVE_DEADLINE_S = 2400
# The teardown's two waits share the suite's 1800 s cleanup budget.
_DELETABLE_DEADLINE_S = 600
_GONE_DEADLINE_S = 1200


def _poll(fn, pred, *, timeout_s, interval_s, description="condition"):
    """Poll fn() until pred(value); raise AssertionError on deadline. Never a bare sleep."""
    deadline = time.monotonic() + timeout_s
    val = fn()
    while not pred(val):
        if time.monotonic() >= deadline:
            raise AssertionError(f"{description} not met within {timeout_s}s; last={val!r}")
        time.sleep(interval_s)
        val = fn()
    return val


def _error_code(exc: ClientError) -> str:
    return exc.response.get("Error", {}).get("Code", "")


def _discover_network(ctx):
    """Two subnets in distinct availability zones of the run's shared network (ctx.network()),
    plus the VPC's default security group."""
    net = ctx.network()
    zones = net.availability_zones
    assert len(zones) >= 2, f"the shared network has subnets in {len(zones)} availability zones, need 2"
    return [net.subnets[az] for az in zones][:2], net.security_group_id


def _cluster_state(msk, arn) -> str:
    """DescribeClusterV2 state, or the sentinel 'GONE' once the cluster is really deleted."""
    try:
        return msk.describe_cluster_v2(ClusterArn=arn)["ClusterInfo"]["State"]
    except ClientError as exc:
        if _error_code(exc) == "NotFoundException":
            return "GONE"
        raise


def _teardown_cluster(msk, arn):
    """Delete the cluster and poll until DescribeClusterV2 reports NotFound. A CREATING cluster
    cannot be deleted, so this first waits for a deletable state; a missed deadline raises, so a
    left-behind cluster is reported rather than silent."""
    state = _poll(
        lambda: _cluster_state(msk, arn),
        lambda s: s not in ("CREATING", "UPDATING", "DELETING"),
        timeout_s=_DELETABLE_DEADLINE_S,
        interval_s=2,
        description=f"cluster {arn} to reach a deletable state",
    )
    if state == "GONE":
        return
    try:
        msk.delete_cluster(ClusterArn=arn)
    except ClientError as exc:
        if _error_code(exc) != "NotFoundException":
            raise
    _poll(
        lambda: _cluster_state(msk, arn),
        lambda s: s == "GONE",
        timeout_s=_GONE_DEADLINE_S,
        interval_s=2,
        description=f"cluster {arn} to disappear",
    )


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """An ACTIVE MSK Serverless cluster with SASL/IAM returns exactly one GetBootstrapBrokers endpoint
    field, the SASL/IAM string, whose endpoints are host:port pairs."""
    msk = ctx.client("kafka")
    subnet_ids, sg_id = _discover_network(ctx)

    name = ctx.unique_name("sim2real-behav-sls-brokers-")
    created = msk.create_cluster_v2(
        ClusterName=name,
        Serverless={
            "VpcConfigs": [{"SubnetIds": subnet_ids, "SecurityGroupIds": [sg_id]}],
            "ClientAuthentication": {"Sasl": {"Iam": {"Enabled": True}}},
        },
        Tags={"sim2real:managed": "true"},
    )
    arn = created["ClusterArn"]
    # Registered before the ARN is used anywhere else.
    ctx.on_cleanup(lambda: _teardown_cluster(msk, arn))
    assert created["ClusterType"] == "SERVERLESS", created

    info = _poll(
        lambda: msk.describe_cluster_v2(ClusterArn=arn)["ClusterInfo"],
        lambda i: i.get("State") in ("ACTIVE", "FAILED"),
        timeout_s=_ACTIVE_DEADLINE_S,
        interval_s=30,
        description=f"serverless cluster {name} to settle",
    )
    assert info["State"] == "ACTIVE", f"serverless cluster settled in {info['State']}: {info}"
    assert info["ClusterType"] == "SERVERLESS", info

    # The auth config we are about to hold GetBootstrapBrokers to, read back from the service.
    sasl = info.get("Serverless", {}).get("ClientAuthentication", {}).get("Sasl", {})
    assert sasl.get("Iam", {}).get("Enabled") is True, (
        f"serverless cluster must report SASL/IAM enabled, got ClientAuthentication="
        f"{info.get('Serverless', {}).get('ClientAuthentication')}"
    )

    resp = msk.get_bootstrap_brokers(ClusterArn=arn)
    present = {k for k in _ALL_ENDPOINT_KEYS if resp.get(k)}
    assert present == {_SERVERLESS_EXPECTED}, (
        f"serverless SASL/IAM cluster must advertise exactly {{{_SERVERLESS_EXPECTED}}}, "
        f"got {sorted(present)}"
    )

    endpoints = [e.strip() for e in resp[_SERVERLESS_EXPECTED].split(",") if e.strip()]
    assert endpoints, f"{_SERVERLESS_EXPECTED} was present but parsed to no endpoints: {resp}"
    for endpoint in endpoints:
        host, sep, port = endpoint.rpartition(":")
        assert sep == ":" and host, f"endpoint is not host:port: {endpoint!r}"
        assert port.isdigit(), (
            f"SASL/IAM endpoints must advertise a numeric port, got {endpoint!r}"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
