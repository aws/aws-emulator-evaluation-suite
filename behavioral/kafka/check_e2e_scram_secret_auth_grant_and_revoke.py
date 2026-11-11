"""e2e-scram-secret-auth-grant-and-revoke."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "e2e-scram-secret-auth-grant-and-revoke"
GROUP = "e2e"
SERVICES = ["kafka"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Associating a SCRAM secret with a SASL/SCRAM-enabled cluster makes it
    appear in ListScramSecrets and the cluster's SASL/SCRAM bootstrap endpoint
    becomes available; disassociating it removes it from the list again."""
    kafka = ctx.client("kafka")
    secretsmanager = ctx.client("secretsmanager")
    kms = ctx.client("kms")

    infra = _create_vpc_infra(ctx)
    key_id = kms.create_key(
        Description="sim2real kafka scram secret key",
        Tags=[{"TagKey": "sim2real:managed", "TagValue": "true"}],
    )["KeyMetadata"]["KeyId"]
    ctx.on_cleanup(lambda: kms.schedule_key_deletion(KeyId=key_id, PendingWindowInDays=7))

    secret_name = ctx.unique_name("AmazonMSK_sim2real-")
    secret_arn = secretsmanager.create_secret(
        Name=secret_name,
        KmsKeyId=key_id,
        SecretString=json.dumps({"username": "sim2real-user", "password": "Sim2Real-Passw0rd!"}),
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )["ARN"]
    ctx.on_cleanup(lambda: secretsmanager.delete_secret(SecretId=secret_arn, ForceDeleteWithoutRecovery=True))

    cluster_arn = _create_provisioned_cluster(ctx, kafka, infra, num_brokers=2)

    assoc = kafka.batch_associate_scram_secret(ClusterArn=cluster_arn, SecretArnList=[secret_arn])
    assert assoc["UnprocessedScramSecrets"] == [], (
        f"expected BatchAssociateScramSecret to process {secret_arn} cleanly, "
        f"got unprocessed={assoc['UnprocessedScramSecrets']}"
    )

    def _cleanup_disassociate():
        secrets = kafka.list_scram_secrets(ClusterArn=cluster_arn).get("SecretArnList", [])
        if secret_arn in secrets:
            try:
                kafka.batch_disassociate_scram_secret(ClusterArn=cluster_arn, SecretArnList=[secret_arn])
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "NotFoundException":
                    raise

    ctx.on_cleanup(_cleanup_disassociate)

    secrets_after_associate = _wait_scram_secrets(ctx, kafka, cluster_arn, secret_arn, present=True, timeout_s=120.0)
    assert secret_arn in secrets_after_associate, (
        f"expected {secret_arn} in ListScramSecrets after association, got {secrets_after_associate}"
    )

    brokers = kafka.get_bootstrap_brokers(ClusterArn=cluster_arn)
    assert brokers.get("BootstrapBrokerStringSaslScram"), (
        "expected a non-empty SASL/SCRAM bootstrap broker string once a SCRAM "
        "secret is associated with a SASL/SCRAM-enabled cluster"
    )

    disassoc = kafka.batch_disassociate_scram_secret(ClusterArn=cluster_arn, SecretArnList=[secret_arn])
    assert disassoc["UnprocessedScramSecrets"] == [], (
        f"expected BatchDisassociateScramSecret to process {secret_arn} cleanly, "
        f"got unprocessed={disassoc['UnprocessedScramSecrets']}"
    )

    secrets_after_disassociate = _wait_scram_secrets(ctx, kafka, cluster_arn, secret_arn, present=False, timeout_s=120.0)
    assert secret_arn not in secrets_after_disassociate, (
        f"expected {secret_arn} to be gone from ListScramSecrets after disassociation, "
        f"got {secrets_after_disassociate}"
    )



def _gone(fn) -> bool:
    """True once fn() raises NotFoundException, False while it succeeds; other errors raise."""
    try:
        fn()
    except ClientError as err:
        if err.response["Error"]["Code"] == "NotFoundException":
            return True
        raise
    return False


def _tag_spec(resource_type: str, name: str) -> dict:
    return {"ResourceType": resource_type, "Tags": [{"Key": "Name", "Value": name}]}


def _create_vpc_infra(ctx) -> dict:
    ec2 = ctx.client("ec2")
    name = ctx.unique_name("sim2real-kafka-scram-")
    vpc_id = ec2.create_vpc(CidrBlock="10.81.0.0/16", TagSpecifications=[_tag_spec("vpc", name)])["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc_id))

    azs = ec2.describe_availability_zones()["AvailabilityZones"]
    az_names = [a["ZoneName"] for a in azs[:2]]
    subnet_ids = []
    for i, az in enumerate(az_names):
        sid = ec2.create_subnet(
            VpcId=vpc_id,
            CidrBlock=f"10.81.{i}.0/24",
            AvailabilityZone=az,
            TagSpecifications=[_tag_spec("subnet", f"{name}-{i}")],
        )["Subnet"]["SubnetId"]
        ctx.on_cleanup(lambda sid=sid: _delete_net(ec2, "delete_subnet", SubnetId=sid))
        subnet_ids.append(sid)

    sg_id = ec2.create_security_group(
        GroupName=name,
        Description="sim2real kafka scram sg",
        VpcId=vpc_id,
        TagSpecifications=[_tag_spec("security-group", name)],
    )["GroupId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_security_group", GroupId=sg_id))
    return {"vpc_id": vpc_id, "subnet_ids": subnet_ids, "sg_id": sg_id}


def _create_provisioned_cluster(ctx, kafka, infra: dict, num_brokers: int = 2) -> str:
    name = ctx.unique_name("sim2real-kafka-scram")
    versions = kafka.list_kafka_versions().get("KafkaVersions", [])
    active = [v for v in versions if v.get("Status", "ACTIVE") == "ACTIVE"]
    kafka_version = (active or versions)[0]["Version"]

    resp = kafka.create_cluster(
        ClusterName=name,
        KafkaVersion=kafka_version,
        NumberOfBrokerNodes=num_brokers,
        ClientAuthentication={"Sasl": {"Scram": {"Enabled": True}}},
        BrokerNodeGroupInfo={
            "InstanceType": "kafka.t3.small",
            "ClientSubnets": infra["subnet_ids"],
            "SecurityGroups": [infra["sg_id"]],
            "StorageInfo": {"EbsStorageInfo": {"VolumeSize": 100}},
        },
        Tags={"sim2real:managed": "true"},
    )
    cluster_arn = resp["ClusterArn"]

    def _cleanup_cluster():
        if _gone(lambda: kafka.describe_cluster(ClusterArn=cluster_arn)):
            return
        try:
            kafka.delete_cluster(ClusterArn=cluster_arn)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NotFoundException":
                raise
        _wait_cluster_gone(ctx, kafka, cluster_arn, timeout_s=1800.0)

    ctx.on_cleanup(_cleanup_cluster)
    _wait_cluster_state(ctx, kafka, cluster_arn, {"ACTIVE"}, timeout_s=1800.0)
    return cluster_arn


def _wait_cluster_state(ctx, kafka, cluster_arn: str, target_states: set, timeout_s: float = 1800.0) -> dict:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        info = kafka.describe_cluster(ClusterArn=cluster_arn)["ClusterInfo"]
        state = info["State"]
        last = state
        if state in target_states:
            return info
        if state == "FAILED":
            raise AssertionError(f"cluster entered FAILED: {info.get('StateInfo')}")
        time.sleep(2)
    raise AssertionError(f"cluster never reached {target_states} (last={last})")


def _wait_cluster_gone(ctx, kafka, cluster_arn: str, timeout_s: float = 1800.0) -> None:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        if _gone(lambda: kafka.describe_cluster(ClusterArn=cluster_arn)):
            return
        time.sleep(2)
    raise AssertionError(f"cluster {cluster_arn} was not deleted within {timeout_s}s")


def _wait_scram_secrets(ctx, kafka, cluster_arn: str, secret_arn: str, present: bool, timeout_s: float = 120.0):
    deadline = time.monotonic() + timeout_s
    last: list[str] = []
    while time.monotonic() < deadline:
        last = kafka.list_scram_secrets(ClusterArn=cluster_arn).get("SecretArnList", [])
        if (secret_arn in last) == present:
            return last
        time.sleep(5.0)
    raise AssertionError(f"ListScramSecrets never reflected present={present} (last={last})")


# AWS-managed ENIs (clusters, endpoints, functions, ...) leave a VPC asynchronously after their
# owner's delete returns, so an immediate DeleteSubnet / DeleteSecurityGroup / DeleteVpc fails with
# DependencyViolation. Wait (bounded) for the ENIs to go, retry DependencyViolation inside the same
# window, and raise a final failure naming the ENIs still attached. The window is shared by all of
# one check's network deletes and fits the 900s cleanup budget.
_NET_TEARDOWN_S = 630.0
_NET_ENI_FILTER = {"VpcId": "vpc-id", "SubnetId": "subnet-id", "GroupId": "group-id"}
_NET_DEADLINES: dict = {}


def _delete_net(client, op, **ident):
    import time as _time

    from botocore.exceptions import ClientError as _ClientError

    held = _NET_DEADLINES.get(id(client))
    if held is None or held[0] is not client:
        held = _NET_DEADLINES[id(client)] = (client, _time.monotonic() + _NET_TEARDOWN_S)
    deadline = held[1]
    flt = [{"Name": _NET_ENI_FILTER[k], "Values": [v]} for k, v in ident.items() if k in _NET_ENI_FILTER]
    while _net_enis(client, flt) and _time.monotonic() < deadline:
        _time.sleep(10)
    while True:
        try:
            return getattr(client, op)(**ident)
        except _ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            if code != "DependencyViolation":
                raise
            if _time.monotonic() >= deadline:
                # Same exception type and code, so a caller catching ClientError still collects it.
                raise type(exc)(
                    {**exc.response, "Error": {**exc.response.get("Error", {}), "Message": (
                        f"{op}({ident}): DependencyViolation after {_NET_TEARDOWN_S}s; "
                        f"ENIs still attached: {_net_enis(client, flt)}"
                    )}},
                    exc.operation_name,
                ) from exc
        _time.sleep(10)


def _net_enis(client, flt):
    from botocore.exceptions import ClientError as _ClientError

    if not flt:
        return []
    try:
        enis = client.describe_network_interfaces(Filters=flt)["NetworkInterfaces"]
    except _ClientError:
        return []  # a diagnostic only: the delete itself still reports its own failure
    return [f"{e['NetworkInterfaceId']}:{e.get('InterfaceType') or e.get('Description', '')[:40]}" for e in enis]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
