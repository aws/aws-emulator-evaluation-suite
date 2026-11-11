"""topic-partition-message-ordering-preserved."""
from __future__ import annotations

import json
import secrets
import ssl
import time

from behavioral_harness import tags

CHECK = "topic-partition-message-ordering-preserved"
GROUP = "ordering"
SERVICES = ["kafka"]

_MANAGED_TAGS = {"sim2real:managed": "true", "sim2real:check": CHECK}
_MANAGED_TAG_LIST = [{"Key": k, "Value": v} for k, v in _MANAGED_TAGS.items()]
_MANAGED_TAG_LIST_KMS = [{"TagKey": k, "TagValue": v} for k, v in _MANAGED_TAGS.items()]


def _route(ctx, bootstrap: str) -> list[str]:
    """Each broker of a bootstrap string as ctx.endpoint_host gives it."""
    pairs = (b.rpartition(":")[::2] for b in bootstrap.split(","))
    return ["%s:%d" % ctx.endpoint_host(h, int(p)) for h, p in pairs]


@tags("axis:happy-path", "cap:c2", "cap:c4", "concern:data-plane", "dp:native", "plane:data")
def run(ctx) -> None:
    """Messages produced in order to a single-partition topic are consumed back in that exact order over
    the Kafka wire protocol: the per-partition FIFO guarantee a faked data plane cannot meet."""
    try:
        import kafka as kafka_client  # noqa: F401  (kafka-python)
    except ImportError:
        raise AssertionError(
            "kafka-python is not installed; cannot perform a native Kafka "
            "protocol produce/consume round-trip against the MSK data plane"
        )

    kafka = ctx.client("kafka")
    username, password = "sim2real-user", secrets.token_urlsafe(18)
    cluster_arn = _create_scram_public_cluster(ctx, "sim2real-ord")
    _associate_scram_user(ctx, cluster_arn, "ord", username, password)
    _grant_scram_acls(ctx, cluster_arn, username)

    topic_name = ctx.unique_name("sim2real-ord-topic-")
    kafka.create_topic(ClusterArn=cluster_arn, TopicName=topic_name, PartitionCount=1, ReplicationFactor=2)
    _wait_topic_active(ctx, cluster_arn, topic_name)

    bootstrap = _bootstrap_servers(ctx, cluster_arn)

    messages = [f"msg-{i:03d}" for i in range(25)]
    producer = _connect_producer_with_retry(bootstrap, username, password, timeout_s=180.0)
    try:
        for m in messages:
            producer.send(topic_name, m.encode("utf-8"))
        producer.flush(timeout=30)
    finally:
        producer.close()

    received = _consume_all(bootstrap, username, password, topic_name, ctx.unique_name("grp-"), expected=len(messages))
    assert received == messages, f"expected ordered messages {messages}, got {received}"


def _pick_kafka_version(ctx) -> str:
    # Standard brokers accept 3.9.x; 4.2.x runs on Express brokers only.
    kafka = ctx.client("kafka")
    status = {v["Version"]: v.get("Status") for v in kafka.list_kafka_versions().get("KafkaVersions", [])}
    if status.get("3.9.x") != "ACTIVE":
        raise AssertionError(f"Kafka 3.9.x is not ACTIVE in ListKafkaVersions: {sorted(status)}")
    return "3.9.x"


def _provision_network(ctx, name_prefix: str, count: int = 2):
    """Provision a dedicated VPC/subnets/security-group for the cluster -- never depends on an
    ambient default VPC, which a freshly provisioned account may not have."""
    ec2 = ctx.client("ec2")

    def _tag_spec(resource_type: str):
        return [{"ResourceType": resource_type, "Tags": _MANAGED_TAG_LIST}]

    vpc_id = ec2.create_vpc(CidrBlock="10.97.0.0/16", TagSpecifications=_tag_spec("vpc"))["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc_id))
    ec2.modify_vpc_attribute(VpcId=vpc_id, EnableDnsSupport={"Value": True})
    ec2.modify_vpc_attribute(VpcId=vpc_id, EnableDnsHostnames={"Value": True})

    igw_id = ec2.create_internet_gateway(TagSpecifications=_tag_spec("internet-gateway"))["InternetGateway"][
        "InternetGatewayId"
    ]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_internet_gateway", InternetGatewayId=igw_id))
    ec2.attach_internet_gateway(InternetGatewayId=igw_id, VpcId=vpc_id)
    ctx.on_cleanup(lambda: _delete_net(ec2, "detach_internet_gateway", InternetGatewayId=igw_id, VpcId=vpc_id))

    azs = [a["ZoneName"] for a in ec2.describe_availability_zones()["AvailabilityZones"][:count]]
    if len(azs) < count:
        raise AssertionError(f"region has fewer than {count} available availability zones")

    rt_id = ec2.create_route_table(VpcId=vpc_id, TagSpecifications=_tag_spec("route-table"))["RouteTable"][
        "RouteTableId"
    ]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_route_table", RouteTableId=rt_id))
    ec2.create_route(RouteTableId=rt_id, DestinationCidrBlock="0.0.0.0/0", GatewayId=igw_id)

    subnet_ids = []
    for i, az in enumerate(azs):
        subnet_id = ec2.create_subnet(
            VpcId=vpc_id,
            CidrBlock=f"10.97.{i}.0/24",
            AvailabilityZone=az,
            TagSpecifications=_tag_spec("subnet"),
        )["Subnet"]["SubnetId"]
        ctx.on_cleanup(lambda sid=subnet_id: _delete_net(ec2, "delete_subnet", SubnetId=sid))
        ec2.modify_subnet_attribute(SubnetId=subnet_id, MapPublicIpOnLaunch={"Value": True})
        assoc_id = ec2.associate_route_table(RouteTableId=rt_id, SubnetId=subnet_id)["AssociationId"]
        ctx.on_cleanup(lambda a=assoc_id: _safe(lambda: ec2.disassociate_route_table(AssociationId=a)))
        subnet_ids.append(subnet_id)

    sg_id = ec2.create_security_group(
        GroupName=ctx.unique_name(f"{name_prefix}-sg-"),
        Description="sim2real kafka behavioral check",
        VpcId=vpc_id,
        TagSpecifications=_tag_spec("security-group"),
    )["GroupId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_security_group", GroupId=sg_id))
    ec2.authorize_security_group_ingress(
        GroupId=sg_id,
        IpPermissions=[
            # 9196 and 9198 are the public SASL/SCRAM and SASL/IAM ports.
            {"IpProtocol": "tcp", "FromPort": port, "ToPort": port,
             "IpRanges": [{"CidrIp": c} for c in ctx.ingress_cidrs()]}
            for port in (9196, 9198)
        ],
    )
    return vpc_id, subnet_ids, sg_id


def _wait_cluster_active(ctx, cluster_arn: str, timeout_s: float = 1800.0, interval_s: float = 30.0):
    kafka = ctx.client("kafka")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        info = kafka.describe_cluster_v2(ClusterArn=cluster_arn)["ClusterInfo"]
        state = info.get("State")
        if state == "ACTIVE":
            return info
        if state == "FAILED":
            raise AssertionError(f"cluster {cluster_arn} entered FAILED state: {info}")
        time.sleep(interval_s)
    raise AssertionError(f"cluster {cluster_arn} did not reach ACTIVE within {timeout_s}s")


def _wait_topic_active(ctx, cluster_arn: str, topic_name: str, timeout_s: float = 180.0, interval_s: float = 5.0):
    kafka = ctx.client("kafka")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        try:
            last = kafka.describe_topic(ClusterArn=cluster_arn, TopicName=topic_name)
        except Exception:
            last = None
        if last and last.get("Status") == "ACTIVE":
            return last
        time.sleep(interval_s)
    raise AssertionError(f"topic {topic_name} did not reach ACTIVE within {timeout_s}s (last: {last})")


def _public_access_configuration(ctx, kafka):
    """A configuration that satisfies MSK's public-access precondition: UpdateConnectivity
    refuses SERVICE_PROVIDED_EIPS unless allow.everyone.if.no.acl.found is false. It lists
    every catalog version so it stays valid for whichever version the cluster gets."""
    catalog_versions = sorted({v["Version"] for v in kafka.list_kafka_versions().get("KafkaVersions", [])})
    config = kafka.create_configuration(
        Name=ctx.unique_name("sim2real-msk-public-cfg-"),
        Description="sim2real: public MSK cluster requires allow.everyone.if.no.acl.found=false",
        KafkaVersions=catalog_versions,
        ServerProperties=b"allow.everyone.if.no.acl.found=false\n",
    )
    ctx.on_cleanup(lambda: kafka.delete_configuration(Arn=config["Arn"]))
    return {"Arn": config["Arn"], "Revision": config["LatestRevision"]["Revision"]}


def _enable_public_access(kafka, cluster_arn, wait_active):
    """CreateClusterV2 accepts only PublicAccess DISABLED; public access is turned on with
    UpdateConnectivity once the cluster is ACTIVE, and the cluster is ACTIVE again after it."""
    current_version = kafka.describe_cluster_v2(ClusterArn=cluster_arn)["ClusterInfo"]["CurrentVersion"]
    kafka.update_connectivity(
        ClusterArn=cluster_arn,
        CurrentVersion=current_version,
        ConnectivityInfo={"PublicAccess": {"Type": "SERVICE_PROVIDED_EIPS"}},
    )
    wait_active()


def _create_scram_public_cluster(ctx, name_prefix: str, configuration=None) -> str:
    kafka = ctx.client("kafka")
    version = _pick_kafka_version(ctx)
    _vpc_id, subnets, sg_id = _provision_network(ctx, name_prefix)

    provisioned = {
        "KafkaVersion": version,
        "NumberOfBrokerNodes": 2,
        "ClientAuthentication": {"Sasl": {"Scram": {"Enabled": True}, "Iam": {"Enabled": True}}},
        "EncryptionInfo": {"EncryptionInTransit": {"ClientBroker": "TLS", "InCluster": True}},
        "BrokerNodeGroupInfo": {
            "InstanceType": "kafka.m5.large",
            "ClientSubnets": subnets,
            "SecurityGroups": [sg_id],
            "ConnectivityInfo": {"PublicAccess": {"Type": "DISABLED"}},
        },
        "ConfigurationInfo": configuration or _public_access_configuration(ctx, kafka),
    }

    cluster_name = ctx.unique_name(f"{name_prefix}-")
    cluster_arn = kafka.create_cluster_v2(
        ClusterName=cluster_name, Provisioned=provisioned, Tags=_MANAGED_TAGS
    )["ClusterArn"]

    def _cleanup():
        # Waits until the cluster is gone, so the network deletes after it can succeed.
        try:
            kafka.delete_cluster(ClusterArn=cluster_arn)
        except kafka.exceptions.NotFoundException:
            return
        deadline = time.monotonic() + 1500.0
        while time.monotonic() < deadline:
            try:
                kafka.describe_cluster_v2(ClusterArn=cluster_arn)
            except kafka.exceptions.NotFoundException:
                return
            time.sleep(20.0)
        raise AssertionError(f"cluster {cluster_arn} still present 1500s after DeleteCluster")

    ctx.on_cleanup(_cleanup)
    _wait_cluster_active(ctx, cluster_arn)
    _enable_public_access(kafka, cluster_arn, lambda: _wait_cluster_active(ctx, cluster_arn))
    return cluster_arn


def _associate_scram_user(ctx, cluster_arn: str, tag: str, username: str, password: str) -> str:
    kafka = ctx.client("kafka")
    kms = ctx.client("kms")
    sm = ctx.client("secretsmanager")

    key_id = kms.create_key(
        Description="sim2real kafka scram secret key", Tags=_MANAGED_TAG_LIST_KMS
    )["KeyMetadata"]["KeyId"]
    ctx.on_cleanup(lambda: _safe(lambda: kms.schedule_key_deletion(KeyId=key_id, PendingWindowInDays=7)))

    secret_name = f"AmazonMSK_{ctx.unique_name(tag)}"
    secret_arn = sm.create_secret(
        Name=secret_name,
        KmsKeyId=key_id,
        SecretString=json.dumps({"username": username, "password": password}),
        Tags=_MANAGED_TAG_LIST,
    )["ARN"]
    ctx.on_cleanup(lambda: _safe(lambda: sm.delete_secret(SecretId=secret_arn, ForceDeleteWithoutRecovery=True)))

    kafka.batch_associate_scram_secret(ClusterArn=cluster_arn, SecretArnList=[secret_arn])
    return secret_arn


def _safe(fn) -> None:
    try:
        fn()
    except Exception:
        pass


def _bootstrap_servers(ctx, cluster_arn: str) -> list[str]:
    kafka = ctx.client("kafka")
    # The public bootstrap string can lag the cluster's return to ACTIVE after UpdateConnectivity.
    deadline = time.monotonic() + 300.0
    bootstrap = None
    while not bootstrap and time.monotonic() < deadline:
        bootstrap = kafka.get_bootstrap_brokers(ClusterArn=cluster_arn).get("BootstrapBrokerStringPublicSaslScram")
        if not bootstrap:
            time.sleep(15.0)
    if not bootstrap:
        raise AssertionError("cluster did not return a public SASL/SCRAM bootstrap broker string")
    return _route(ctx, bootstrap)


def _connect_producer_with_retry(bootstrap, username: str, password: str, timeout_s: float = 180.0, interval_s: float = 10.0):
    from kafka import KafkaProducer

    deadline = time.monotonic() + timeout_s
    last_exc: Exception | None = None
    while time.monotonic() < deadline:
        try:
            producer = KafkaProducer(
                bootstrap_servers=bootstrap,
                security_protocol="SASL_SSL",
                ssl_context=ssl._create_unverified_context(),
                sasl_mechanism="SCRAM-SHA-512",
                sasl_plain_username=username,
                sasl_plain_password=password,
                api_version=(2, 8, 1),
                request_timeout_ms=20000,
            )
            return producer
        except Exception as exc:  # broker-side SCRAM secret propagation can lag briefly
            last_exc = exc
            time.sleep(interval_s)
    raise AssertionError(f"could not connect a SASL/SCRAM producer within {timeout_s}s: {last_exc}")


def _consume_all(bootstrap, username: str, password: str, topic_name: str, group_id: str, expected: int, timeout_s: float = 60.0):
    from kafka import KafkaConsumer

    consumer = KafkaConsumer(
        topic_name,
        bootstrap_servers=bootstrap,
        security_protocol="SASL_SSL",
        ssl_context=ssl._create_unverified_context(),
        sasl_mechanism="SCRAM-SHA-512",
        sasl_plain_username=username,
        sasl_plain_password=password,
        api_version=(2, 8, 1),
        auto_offset_reset="earliest",
        enable_auto_commit=False,
        group_id=group_id,
        consumer_timeout_ms=int(timeout_s * 1000),
    )
    values = []
    try:
        for record in consumer:
            values.append(record.value.decode("utf-8"))
            if len(values) >= expected:
                break
    finally:
        consumer.close()
    return values


# EC2 network teardown waits for AWS-managed ENIs to leave before it deletes. A load balancer,
# directory, endpoint, cluster, function or instance in this VPC deletes ASYNCHRONOUSLY: its delete
# returns while its ENIs still sit in the subnet / security group, so an immediate DeleteSubnet /
# DeleteSecurityGroup / DeleteVpc fails with DependencyViolation -- and swallowing that leaked the
# VPC while the check PASSED. So wait (bounded) for the resource's ENIs to go, retry
# DependencyViolation inside the same window, and raise a final failure naming the ENIs still
# attached. Every other error propagates. Teardown-only: nothing run() executes calls this, so it
# cannot change the verdict. The window is shared by all of one check's network deletes.
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


# ===== Kafka ACLs for the SCRAM user, granted over the public SASL/IAM listener =====
# The public-access precondition (allow.everyone.if.no.acl.found=false) leaves the SCRAM user with
# no grant: its produce fails with TopicAuthorizationFailed and its consume with
# GroupAuthorizationFailed (both observed on real AWS), and MSK has no control-plane API for Kafka
# ACLs. The cluster therefore also turns on IAM access control, and the run's own IAM identity,
# authorized by IAM rather than by ACLs, grants the ACLs through the Kafka CreateAcls API on the
# public SASL/IAM port 9198 ("You can invoke Apache Kafka ACL APIs for an MSK cluster that uses IAM
# access control", https://docs.aws.amazon.com/msk/latest/developerguide/iam-access-control.html).
def _iam_token_provider(client):
    """An OAUTHBEARER token provider for MSK IAM: a SigV4-presigned kafka-cluster:Connect URL,
    base64url-encoded, signed with the credentials the run's own kafka client uses."""
    import base64

    from botocore.auth import SigV4QueryAuth
    from botocore.awsrequest import AWSRequest

    try:
        from kafka.net.sasl.oauth import AbstractTokenProvider
    except ImportError:  # kafka-python before 3.0
        from kafka.sasl.oauth import AbstractTokenProvider

    region = client.meta.region_name
    credentials = client._request_signer._credentials

    class _Provider(AbstractTokenProvider):
        def token(self):
            request = AWSRequest(
                method="GET", url=f"https://kafka.{region}.amazonaws.com/?Action=kafka-cluster%3AConnect"
            )
            SigV4QueryAuth(credentials.get_frozen_credentials(), "kafka-cluster", region, expires=900).add_auth(request)
            signed = request.url + "&User-Agent=sim2real-kafka-check"
            return base64.urlsafe_b64encode(signed.encode()).decode().rstrip("=")

    return _Provider()


def _grant_scram_acls(ctx, cluster_arn: str, username: str, timeout_s: float = 300.0) -> None:
    """ALLOW ALL on every topic and every consumer group for User:<username>."""
    import ssl as _ssl

    from kafka.admin import (
        ACL,
        ACLOperation,
        ACLPermissionType,
        ACLResourcePatternType,
        KafkaAdminClient,
        ResourcePattern,
        ResourceType,
    )

    kafka = ctx.client("kafka")
    deadline = time.monotonic() + timeout_s
    bootstrap = None
    while not bootstrap and time.monotonic() < deadline:
        bootstrap = kafka.get_bootstrap_brokers(ClusterArn=cluster_arn).get("BootstrapBrokerStringPublicSaslIam")
        if not bootstrap:
            time.sleep(15.0)
    if not bootstrap:
        raise AssertionError("cluster returned no public SASL/IAM bootstrap broker string")
    pairs = (b.rpartition(":")[::2] for b in bootstrap.split(","))
    brokers = ["%s:%d" % ctx.endpoint_host(h, int(p)) for h, p in pairs]
    acls = [
        ACL(
            principal=f"User:{username}",
            host="*",
            operation=ACLOperation.ALL,
            permission_type=ACLPermissionType.ALLOW,
            resource_pattern=ResourcePattern(resource_type, "*", ACLResourcePatternType.LITERAL),
        )
        for resource_type in (ResourceType.TOPIC, ResourceType.GROUP)
    ]
    last_exc = None
    while time.monotonic() < deadline:
        try:
            admin = KafkaAdminClient(
                bootstrap_servers=brokers,
                security_protocol="SASL_SSL",
                ssl_context=_ssl._create_unverified_context(),
                sasl_mechanism="OAUTHBEARER",
                sasl_oauth_token_provider=_iam_token_provider(kafka),
                request_timeout_ms=30000,
            )
        except Exception as exc:  # the public IAM listener can lag the cluster's return to ACTIVE
            last_exc = exc
            time.sleep(15.0)
            continue
        try:
            result = admin.create_acls(acls)
        finally:
            admin.close()
        assert not result["failed"], f"CreateAcls for User:{username} failed: {result['failed']}"
        return
    raise AssertionError(f"could not reach the public SASL/IAM listener within {timeout_s}s: {last_exc!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
