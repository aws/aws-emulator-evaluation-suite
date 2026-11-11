"""delete-custom-plugin-in-use-by-connector-rejected."""
from __future__ import annotations

import base64
import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-custom-plugin-in-use-by-connector-rejected"
GROUP = "overly-permissive"
SERVICES = ["kafkaconnect"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteCustomPlugin is rejected while a connector still references it; once the referencing
    connector is deleted, deleting the same plugin succeeds."""
    kc = ctx.client("kafkaconnect")
    prereqs = _provision_connect_prereqs(ctx)
    plugin_arn = prereqs["plugin_arn"]

    connector_name = ctx.unique_name("sim2real-kc-inuse-")
    created = _create_connector_with_retry(kc, _connector_create_kwargs(prereqs, connector_name))
    connector_arn = created["connectorArn"]
    ctx.on_cleanup(lambda: _best_effort_delete_connector(kc, connector_arn))

    # Break exactly one thing: try to delete the plugin while the connector still references it.
    code, message = _client_error(lambda: kc.delete_custom_plugin(customPluginArn=plugin_arn))
    assert code == "BadRequestException", code
    assert message == (
        "You can't delete a custom plugin being used by one or more connectors. This custom plugin "
        f"is used by the connector with arn {connector_arn}, and possibly others. Please delete "
        "connectors using this custom plugin and try again."
    ), message

    # Effect absent: the plugin is still there, still ACTIVE.
    described = kc.describe_custom_plugin(customPluginArn=plugin_arn)
    assert described["customPluginState"] == "ACTIVE", described["customPluginState"]

    # Retire the connector first...
    _poll_until(
        lambda: kc.describe_connector(connectorArn=connector_arn)["connectorState"],
        lambda s: s != "CREATING",
        timeout_s=1500,
        interval_s=15,
    )
    kc.delete_connector(connectorArn=connector_arn)
    gone_code, gone_message = _wait_for_error(
        lambda: kc.describe_connector(connectorArn=connector_arn), timeout_s=300, interval_s=5
    )
    assert gone_code == "NotFoundException", gone_code
    assert gone_message == (
        "Invalid parameter connectorArn: The requested resource doesn\u2019t exist."
    ), gone_message

    # Positive control: now that nothing references it, deleting the plugin succeeds.
    kc.delete_custom_plugin(customPluginArn=plugin_arn)
    final_code, final_message = _wait_for_error(
        lambda: kc.describe_custom_plugin(customPluginArn=plugin_arn), timeout_s=120, interval_s=3
    )
    assert final_code == "NotFoundException", final_code
    assert final_message == (
        "Invalid parameter customPluginArn: The requested resource doesn\u2019t exist."
    ), final_message


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
        CidrBlock="10.94.0.0/16",
        TagSpecifications=[
            {"ResourceType": "vpc", "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-kc-vpc-")}]}
        ],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: ec2.delete_vpc(VpcId=vpc_id))

    azs = [z["ZoneName"] for z in ec2.describe_availability_zones()["AvailabilityZones"][:2]]
    subnet_ids = []
    for i, az in enumerate(azs):
        subnet_id = ec2.create_subnet(
            VpcId=vpc_id,
            CidrBlock=f"10.94.{i}.0/24",
            AvailabilityZone=az,
            TagSpecifications=[
                {"ResourceType": "subnet", "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-kc-subnet-")}]}
            ],
        )["Subnet"]["SubnetId"]
        subnet_ids.append(subnet_id)
        ctx.on_cleanup(lambda sid=subnet_id: ec2.delete_subnet(SubnetId=sid))

    sg_id = ec2.create_security_group(
        VpcId=vpc_id,
        GroupName=ctx.unique_name("sim2real-kc-sg-"),
        Description="sim2real kafkaconnect fixture",
    )["GroupId"]
    ctx.on_cleanup(lambda: ec2.delete_security_group(GroupId=sg_id))

    role_name = ctx.unique_name("sim2real-kc-role-")
    role_arn = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=_connect_trust_policy())["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    bucket = ctx.unique_name("sim2real-kc-fixture-").lower()
    if ctx.region == "us-east-1":
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
    ctx.on_cleanup(lambda: _best_effort_delete_plugin(kc, plugin_arn))
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


def _best_effort_delete_plugin(kc, plugin_arn: str) -> None:
    try:
        kc.delete_custom_plugin(customPluginArn=plugin_arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NotFoundException":
            raise


def _client_error(fn):
    """Call fn(); return its botocore (code, message). An unexpected success raises, so an
    emulator that accepts what AWS refuses fails loudly instead of reading as a code mismatch."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError but the call succeeded: {result!r}")


def _wait_for_error(fn, *, timeout_s=60.0, interval_s=2.0):
    """Re-call fn() until it raises a ClientError and return its (code, message); raise if it
    still succeeds when the budget runs out."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        try:
            last = fn()
        except ClientError as e:
            return e.response["Error"]["Code"], e.response["Error"].get("Message")
        time.sleep(interval_s)
    raise AssertionError(f"the call still succeeded after {timeout_s}s; last={last!r}")


def _best_effort_delete_connector(kc, connector_arn: str) -> None:
    try:
        kc.delete_connector(connectorArn=connector_arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NotFoundException":
            raise


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
