"""scram-secret-disassociation-immediate-auth-revocation."""
from __future__ import annotations

import json
import secrets
import ssl
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "scram-secret-disassociation-immediate-auth-revocation"
GROUP = "visibility-timeout-ttl"
SERVICES = ["kafka"]


def _route(ctx, bootstrap: str) -> list[str]:
    """Each broker of a bootstrap string as ctx.endpoint_host gives it."""
    pairs = (b.rpartition(":")[::2] for b in bootstrap.split(","))
    return ["%s:%d" % ctx.endpoint_host(h, int(p)) for h, p in pairs]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:data-plane", "dp:native", "plane:data")
def run(ctx) -> None:
    """A disassociated SCRAM secret leaves ListScramSecrets at once and its credentials are rejected by
    the brokers within the documented propagation window (up to 10 minutes), while a still-associated
    secret keeps authenticating (positive control)."""
    try:
        import kafka as kafka_client  # noqa: F401  (kafka-python)
    except ImportError:
        raise AssertionError(
            "kafka-python is not installed; cannot perform a native Kafka SASL/SCRAM "
            "authentication round-trip against the MSK data plane"
        )

    kafka = ctx.client("kafka")
    user_a = ("sim2real-user-a", secrets.token_urlsafe(18))
    user_b = ("sim2real-user-b", secrets.token_urlsafe(18))

    cluster_arn = _create_scram_public_cluster(ctx, "sim2real-revoke")
    secret_a = _create_scram_secret(ctx, "revokea", *user_a)
    secret_b = _create_scram_secret(ctx, "revokeb", *user_b)
    kafka.batch_associate_scram_secret(ClusterArn=cluster_arn, SecretArnList=[secret_a, secret_b])

    bootstrap = _bootstrap_servers(ctx, cluster_arn)

    # Both secrets authenticate successfully before disassociation.
    _assert_auth_succeeds(bootstrap, *user_a, timeout_s=180.0)
    _assert_auth_succeeds(bootstrap, *user_b, timeout_s=60.0)

    resp = kafka.batch_disassociate_scram_secret(ClusterArn=cluster_arn, SecretArnList=[secret_a])
    assert resp.get("UnprocessedScramSecrets", []) == [], f"disassociation reported failures: {resp}"

    remaining = kafka.list_scram_secrets(ClusterArn=cluster_arn).get("SecretArnList", [])
    assert secret_a not in remaining, f"disassociated secret {secret_a} still listed: {remaining}"
    assert secret_b in remaining, f"unrelated secret {secret_b} unexpectedly missing: {remaining}"

    # A new connection with the removed secret is rejected once the brokers have synced.
    _assert_auth_fails(bootstrap, *user_a, timeout_s=900.0)

    # Positive control: the still-associated secret keeps working.
    _assert_auth_succeeds(bootstrap, *user_b, timeout_s=60.0)


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


def _pick_kafka_version(ctx) -> str:
    # Standard brokers accept 3.9.x; 4.2.x runs on Express brokers only.
    kafka = ctx.client("kafka")
    status = {v["Version"]: v.get("Status") for v in kafka.list_kafka_versions().get("KafkaVersions", [])}
    if status.get("3.9.x") != "ACTIVE":
        raise AssertionError(f"Kafka 3.9.x is not ACTIVE in ListKafkaVersions: {sorted(status)}")
    return "3.9.x"


def _pick_subnets(ctx, count: int):
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "isDefault", "Values": ["true"]}]).get("Vpcs", [])
    if not vpcs:
        raise AssertionError("no default VPC available in this account/region to host a test MSK cluster")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}]).get("Subnets", [])
    by_az: dict[str, str] = {}
    for s in subnets:
        by_az.setdefault(s["AvailabilityZone"], s["SubnetId"])
    chosen = list(by_az.values())[:count]
    if len(chosen) < count:
        raise AssertionError(f"default VPC has fewer than {count} distinct availability zones available")
    return vpc_id, chosen


def _create_runner_security_group(ctx, vpc_id: str, name: str) -> str:
    """A group admitting only the runner's egress CIDRs on 9196, the public SASL/SCRAM port."""
    ec2 = ctx.client("ec2")
    sg_id = ec2.create_security_group(
        GroupName=name, Description="sim2real kafka behavioral check", VpcId=vpc_id
    )["GroupId"]

    def _cleanup():
        # Runs after the cluster delete has waited; broker ENIs can still hold the group briefly.
        from botocore.exceptions import ClientError

        deadline = time.monotonic() + 600.0
        while True:
            try:
                ec2.delete_security_group(GroupId=sg_id)
                return
            except ClientError as exc:
                code = exc.response.get("Error", {}).get("Code")
                if code == "InvalidGroup.NotFound":
                    return
                if code != "DependencyViolation" or time.monotonic() >= deadline:
                    raise
            time.sleep(15.0)

    ctx.on_cleanup(_cleanup)
    ec2.authorize_security_group_ingress(
        GroupId=sg_id,
        IpPermissions=[
            {"IpProtocol": "tcp", "FromPort": 9196, "ToPort": 9196,
             "IpRanges": [{"CidrIp": c} for c in ctx.ingress_cidrs()]}
        ],
    )
    return sg_id


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


def _create_scram_public_cluster(ctx, name_prefix: str) -> str:
    kafka = ctx.client("kafka")
    version = _pick_kafka_version(ctx)
    vpc_id, subnets = _pick_subnets(ctx, 2)
    sg_id = _create_runner_security_group(ctx, vpc_id, ctx.unique_name(f"{name_prefix}-sg-"))
    configuration = _public_access_configuration(ctx, kafka)

    cluster_name = ctx.unique_name(f"{name_prefix}-")
    cluster_arn = kafka.create_cluster_v2(
        ClusterName=cluster_name,
        Provisioned={
            "KafkaVersion": version,
            "NumberOfBrokerNodes": 2,
            "ClientAuthentication": {"Sasl": {"Scram": {"Enabled": True}}},
            "EncryptionInfo": {"EncryptionInTransit": {"ClientBroker": "TLS", "InCluster": True}},
            "BrokerNodeGroupInfo": {
                "InstanceType": "kafka.m5.large",
                "ClientSubnets": subnets,
                "SecurityGroups": [sg_id],
                "ConnectivityInfo": {"PublicAccess": {"Type": "DISABLED"}},
            },
            "ConfigurationInfo": configuration,
        },
    )["ClusterArn"]

    def _cleanup():
        # Waits until the cluster is gone, so the security group delete after it can succeed.
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


def _create_scram_secret(ctx, tag: str, username: str, password: str) -> str:
    kms = ctx.client("kms")
    sm = ctx.client("secretsmanager")

    key_id = kms.create_key(Description="sim2real kafka scram secret key")["KeyMetadata"]["KeyId"]
    ctx.on_cleanup(lambda: _safe(lambda: kms.schedule_key_deletion(KeyId=key_id, PendingWindowInDays=7)))

    secret_name = f"AmazonMSK_{ctx.unique_name(tag)}"
    secret_arn = sm.create_secret(
        Name=secret_name,
        KmsKeyId=key_id,
        SecretString=json.dumps({"username": username, "password": password}),
    )["ARN"]
    ctx.on_cleanup(lambda: _safe(lambda: sm.delete_secret(SecretId=secret_arn, ForceDeleteWithoutRecovery=True)))
    return secret_arn


def _safe(fn) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NotFoundException", "ResourceNotFoundException"):
            raise


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


def _scram_auth_outcome(bootstrap, username: str, password: str, timeout_s: float = 30.0) -> str:
    """"ok" when a fresh client completes SASL/SCRAM and a metadata round trip; "rejected" when a
    broker answers the SASL exchange with an authentication failure. Anything else raises, so a
    network failure is never read as a rejection.

    kafka-python retries a failed bootstrap until its deadline and then raises a generic timeout,
    so the authentication failure itself is taken from the client's own log records."""
    import logging

    from kafka import KafkaAdminClient
    from kafka.errors import SaslAuthenticationFailedError

    rejections: list = []

    class _Recorder(logging.Handler):
        def emit(self, record):
            args = record.args if isinstance(record.args, tuple) else (record.args,)
            rejections.extend(a for a in args if isinstance(a, SaslAuthenticationFailedError))

    recorder = _Recorder()
    logger = logging.getLogger("kafka")
    logger.addHandler(recorder)
    try:
        admin = KafkaAdminClient(
            bootstrap_servers=bootstrap,
            security_protocol="SASL_SSL",
            ssl_context=ssl._create_unverified_context(),
            sasl_mechanism="SCRAM-SHA-512",
            sasl_plain_username=username,
            sasl_plain_password=password,
            request_timeout_ms=15000,
            bootstrap_timeout_ms=int(timeout_s * 1000),
        )
    except Exception as exc:
        if rejections:
            return "rejected"
        raise AssertionError(
            f"SASL/SCRAM probe for {username!r} failed without an authentication verdict: {exc!r}"
        ) from exc
    finally:
        logger.removeHandler(recorder)
    try:
        admin.list_topics()
    finally:
        admin.close()
    return "ok"


def _assert_auth_succeeds(bootstrap, username: str, password: str, timeout_s: float = 60.0, interval_s: float = 10.0) -> None:
    deadline = time.monotonic() + timeout_s
    outcome = None
    while time.monotonic() < deadline:
        outcome = _scram_auth_outcome(bootstrap, username, password)
        if outcome == "ok":
            return
        time.sleep(interval_s)  # broker-side SCRAM secret propagation lags on first use
    raise AssertionError(f"expected SASL/SCRAM auth for {username!r} to succeed within {timeout_s}s, last {outcome!r}")


def _assert_auth_fails(bootstrap, username: str, password: str, timeout_s: float = 900.0, interval_s: float = 30.0) -> None:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        if _scram_auth_outcome(bootstrap, username, password) == "rejected":
            return
        time.sleep(interval_s)
    raise AssertionError(
        f"expected SASL/SCRAM auth for {username!r} to be rejected within {timeout_s}s of disassociation, "
        "but it kept succeeding"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
