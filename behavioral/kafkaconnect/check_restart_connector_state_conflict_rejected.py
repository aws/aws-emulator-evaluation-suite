"""restart-connector-state-conflict-rejected."""
from __future__ import annotations

import base64
import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "restart-connector-state-conflict-rejected"
GROUP = "overly-permissive"
SERVICES = ["kafkaconnect"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """RestartConnector requires the connector to be RUNNING or PAUSED: it rejects a connector
    still in CREATING, and rejects the identical call again with the identical code and message
    once the connector settles into FAILED; neither rejection is tracked as a ConnectorOperation."""
    kc = ctx.client("kafkaconnect")
    prereqs = _provision_connect_prereqs(ctx)

    connector_name = ctx.unique_name("sim2real-kc-restart-")
    created = _create_connector_with_retry(kc, _connector_create_kwargs(prereqs, connector_name))
    connector_arn = created["connectorArn"]
    ctx.on_cleanup(lambda: _delete_connector_and_wait(kc, connector_arn))
    assert created["connectorState"] == "CREATING", created["connectorState"]

    state_gate_message = (
        "Invalid parameter connectorArn: This operation is only valid for resources that are in "
        "one of the following states: [RUNNING, PAUSED]"
    )

    # Break exactly one thing: restart a connector that is still CREATING.
    code, message = _client_error(lambda: kc.restart_connector(connectorArn=connector_arn))
    assert code == "BadRequestException", code
    assert message == state_gate_message, message

    # Effect absent: no restart operation was recorded for this connector.
    ops_after_creating = kc.list_connector_operations(connectorArn=connector_arn)["connectorOperations"]
    assert ops_after_creating == [], ops_after_creating

    final_state = _poll_until(
        lambda: kc.describe_connector(connectorArn=connector_arn)["connectorState"],
        lambda s: s != "CREATING",
        timeout_s=900,
        interval_s=15,
    )
    assert final_state == "FAILED", final_state

    # Control: the identical call fails again, with the identical code and message, once the
    # connector has left CREATING. RestartConnector's state gate names RUNNING and PAUSED only, so
    # a FAILED connector is rejected exactly like a CREATING one -- never reported as success.
    control_code, control_message = _client_error(lambda: kc.restart_connector(connectorArn=connector_arn))
    assert control_code == "BadRequestException", control_code
    assert control_message == state_gate_message, control_message

    ops_after_failed = kc.list_connector_operations(connectorArn=connector_arn)["connectorOperations"]
    assert ops_after_failed == [], ops_after_failed


def _minimal_plugin_zip_bytes() -> bytes:
    import io
    import zipfile

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("META-INF/MANIFEST.MF", "Manifest-Version: 1.0\n")
    return buf.getvalue()


def _connect_trust_policy() -> str:
    return json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Service": "kafkaconnect.amazonaws.com"},
                    "Action": "sts:AssumeRole",
                }
            ],
        }
    )


def _provision_connect_prereqs(ctx) -> dict:
    ec2 = ctx.client("ec2")
    iam = ctx.client("iam")
    s3 = ctx.client("s3")
    kc = ctx.client("kafkaconnect")

    vpc_id = ec2.create_vpc(
        CidrBlock="10.92.0.0/16",
        TagSpecifications=[
            {"ResourceType": "vpc", "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-kc-vpc-")}]}
        ],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc_id))

    azs = [z["ZoneName"] for z in ec2.describe_availability_zones()["AvailabilityZones"][:2]]
    subnet_ids = []
    for i, az in enumerate(azs):
        subnet_id = ec2.create_subnet(
            VpcId=vpc_id,
            CidrBlock=f"10.92.{i}.0/24",
            AvailabilityZone=az,
            TagSpecifications=[
                {"ResourceType": "subnet", "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-kc-subnet-")}]}
            ],
        )["Subnet"]["SubnetId"]
        subnet_ids.append(subnet_id)
        ctx.on_cleanup(lambda sid=subnet_id: _delete_net(ec2, "delete_subnet", SubnetId=sid))

    sg_id = ec2.create_security_group(
        VpcId=vpc_id,
        GroupName=ctx.unique_name("sim2real-kc-sg-"),
        Description="sim2real kafkaconnect fixture",
    )["GroupId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_security_group", GroupId=sg_id))

    role_name = ctx.unique_name("sim2real-kc-role-")
    role_arn = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=_connect_trust_policy())["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    bucket = ctx.unique_name("sim2real-kc-fixture-").lower()
    if ctx.region == "us-east-1":  # S3 rejects an explicit LocationConstraint for this one region

        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    ctx.on_cleanup(lambda: s3.delete_bucket(Bucket=bucket))
    key = "plugin.zip"
    s3.put_object(Bucket=bucket, Key=key, Body=_minimal_plugin_zip_bytes())
    ctx.on_cleanup(lambda: s3.delete_object(Bucket=bucket, Key=key))

    plugin_arn = kc.create_custom_plugin(
        name=ctx.unique_name("sim2real-kc-plugin-"),
        contentType="ZIP",
        location={"s3Location": {"bucketArn": f"arn:aws:s3:::{bucket}", "fileKey": key}},
    )["customPluginArn"]
    ctx.on_cleanup(lambda: kc.delete_custom_plugin(customPluginArn=plugin_arn))
    _poll_until(
        lambda: kc.describe_custom_plugin(customPluginArn=plugin_arn)["customPluginState"],
        lambda s: s in ("ACTIVE", "CREATE_FAILED"),
        timeout_s=180,
        interval_s=3,
    )

    props = base64.b64encode(
        b"key.converter=org.apache.kafka.connect.storage.StringConverter\n"
        b"value.converter=org.apache.kafka.connect.storage.StringConverter\n"
    ).decode()
    wc_arn = kc.create_worker_configuration(
        name=ctx.unique_name("sim2real-kc-workercfg-"), propertiesFileContent=props
    )["workerConfigurationArn"]
    ctx.on_cleanup(lambda: kc.delete_worker_configuration(workerConfigurationArn=wc_arn))

    return {
        "subnet_ids": subnet_ids,
        "security_group_id": sg_id,
        "role_arn": role_arn,
        "plugin_arn": plugin_arn,
        "worker_configuration_arn": wc_arn,
    }


def _connector_create_kwargs(prereqs: dict, connector_name: str) -> dict:
    return dict(
        connectorName=connector_name,
        connectorConfiguration={
            "connector.class": "com.sim2real.nonexistent.NoSuchConnector",
            "tasks.max": "1",
            "topics": "sim2real-test-topic",
            "key.converter": "org.apache.kafka.connect.storage.StringConverter",
            "value.converter": "org.apache.kafka.connect.storage.StringConverter",
        },
        kafkaCluster={
            "apacheKafkaCluster": {
                "bootstrapServers": "b-1.sim2real-nonexistent-cluster.kafka.example.internal:9092",
                "vpc": {"subnets": prereqs["subnet_ids"], "securityGroups": [prereqs["security_group_id"]]},
            }
        },
        kafkaClusterClientAuthentication={"authenticationType": "NONE"},
        kafkaClusterEncryptionInTransit={"encryptionType": "PLAINTEXT"},
        kafkaConnectVersion="2.7.1",
        plugins=[{"customPlugin": {"customPluginArn": prereqs["plugin_arn"], "revision": 1}}],
        serviceExecutionRoleArn=prereqs["role_arn"],
        capacity={"provisionedCapacity": {"mcuCount": 1, "workerCount": 1}},
        workerConfiguration={"workerConfigurationArn": prereqs["worker_configuration_arn"], "revision": 1},
    )


def _create_connector_with_retry(kc, kwargs: dict, attempts: int = 6, delay_s: float = 10.0):
    last_exc = None
    for _ in range(attempts):
        try:
            return kc.create_connector(**kwargs)
        except ClientError as e:
            if e.response["Error"]["Code"] == "ForbiddenException":
                last_exc = e
                time.sleep(delay_s)
                continue
            raise
    raise last_exc


def _delete_connector_and_wait(kc, connector_arn: str, timeout_s: float = 600.0) -> None:
    try:
        kc.delete_connector(connectorArn=connector_arn)
    except ClientError as e:
        if e.response["Error"]["Code"] == "NotFoundException":
            return
        raise
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            kc.describe_connector(connectorArn=connector_arn)
        except ClientError as e:
            if e.response["Error"]["Code"] == "NotFoundException":
                return
            raise
        time.sleep(5)
    raise AssertionError(f"connector {connector_arn} still present {timeout_s}s after DeleteConnector")


# EC2 network teardown waits for AWS-managed ENIs to leave before it deletes. The connector's own
# delete returns while its ENIs still sit in the subnet / security group, so an immediate
# DeleteSubnet / DeleteSecurityGroup / DeleteVpc can fail with DependencyViolation. Wait (bounded)
# for the resource's ENIs to go, retry DependencyViolation inside the same window, and raise a final
# failure naming the ENIs still attached. Every other error propagates. Teardown-only: nothing run()
# executes calls this, so it cannot change the verdict.
_NET_TEARDOWN_S = 630.0
_NET_ENI_FILTER = {"VpcId": "vpc-id", "SubnetId": "subnet-id", "GroupId": "group-id"}
_NET_DEADLINES: dict = {}


def _delete_net(client, op, **ident):
    held = _NET_DEADLINES.get(id(client))
    if held is None or held[0] is not client:
        held = _NET_DEADLINES[id(client)] = (client, time.monotonic() + _NET_TEARDOWN_S)
    deadline = held[1]
    flt = [{"Name": _NET_ENI_FILTER[k], "Values": [v]} for k, v in ident.items() if k in _NET_ENI_FILTER]
    while _net_enis(client, flt) and time.monotonic() < deadline:
        time.sleep(10)
    while True:
        try:
            return getattr(client, op)(**ident)
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            if code != "DependencyViolation":
                raise
            if time.monotonic() >= deadline:
                raise type(exc)(
                    {**exc.response, "Error": {**exc.response.get("Error", {}), "Message": (
                        f"{op}({ident}): DependencyViolation after {_NET_TEARDOWN_S}s; "
                        f"ENIs still attached: {_net_enis(client, flt)}"
                    )}},
                    exc.operation_name,
                ) from exc
        time.sleep(10)


def _net_enis(client, flt):
    if not flt:
        return []
    try:
        enis = client.describe_network_interfaces(Filters=flt)["NetworkInterfaces"]
    except ClientError:
        return []  # a diagnostic only: the delete itself still reports its own failure
    return [e["NetworkInterfaceId"] for e in enis]


def _client_error(fn):
    """Call fn(); return its (code, message). An unexpected SUCCESS raises, because an
    over-permissive target accepting a call real AWS rejects is the strongest signal available
    and must not be graded as an error-code mismatch."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
