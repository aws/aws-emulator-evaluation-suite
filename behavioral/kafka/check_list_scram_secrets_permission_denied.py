"""list-scram-secrets-permission-denied."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "list-scram-secrets-permission-denied"
GROUP = "overly-permissive"
SERVICES = ["kafka"]

_SESSION_NAME = "sim2real-behav-zero-perm"


@tags("axis:rejection", "cap:c7", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ListScramSecrets by a principal with no kafka permissions fails with the exact IAM
    AccessDeniedException, while the default caller succeeds and granting that same role the
    missing permission lets the identical call succeed."""
    kafka = ctx.client("kafka")
    cluster_arn = _create_provisioned_cluster(ctx)

    # Positive control: the default (permitted) caller can list scram secrets.
    control = kafka.list_scram_secrets(ClusterArn=cluster_arn)
    assert control["SecretArnList"] == [], (
        f"expected no scram secrets on a freshly created cluster, got {control['SecretArnList']!r}"
    )

    role_name, role_arn, deny_policy_name = _create_zero_permission_role(ctx)
    restricted_kafka = _client_with_creds(ctx, "kafka", _assume_role(ctx, role_arn))

    account_id = role_arn.split(":")[4]
    # A plain IAM identity-policy deny surfaces as AccessDeniedException; ForbiddenException is
    # reserved for MSK's own resource-policy checks (e.g. a cluster policy).
    expected = (
        "AccessDeniedException",
        f"User: arn:aws:sts::{account_id}:assumed-role/{role_name}/{_SESSION_NAME} is not "
        f"authorized to perform: kafka:ListScramSecrets on resource: {cluster_arn} with an "
        f"explicit deny in an identity-based policy",
    )
    denied = _error_code(lambda: restricted_kafka.list_scram_secrets(ClusterArn=cluster_arn))
    assert denied == expected, (
        f"expected the zero-permission caller to be rejected with {expected!r}, got {denied!r}"
    )

    # Granting exactly the missing permission on the same credentials proves the rejection
    # was the absent permission and nothing else about the identity, cluster or request.
    iam = ctx.client("iam")
    iam.delete_role_policy(RoleName=role_name, PolicyName=deny_policy_name)
    allow_policy_name = "allow-list-scram-secrets"
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName=allow_policy_name,
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [{"Effect": "Allow", "Action": "kafka:ListScramSecrets", "Resource": "*"}],
            }
        ),
    )
    ctx.on_cleanup(lambda: _delete_role_policy_best_effort(iam, role_name, allow_policy_name))

    restored = _retry_until_no_error(
        lambda: restricted_kafka.list_scram_secrets(ClusterArn=cluster_arn)
    )
    assert restored["SecretArnList"] == [], (
        f"expected the identical call to succeed once the permission is granted, got {restored!r}"
    )


def _error_code(fn):
    """Call fn(); return (Error.Code, Error.Message) of the ClientError it raises.

    An unexpected success raises, so an over-permissive accept is not reported as a code mismatch.
    """
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _retry_until_no_error(fn, timeout_s=900.0, interval_s=10.0):
    """IAM policy changes are eventually consistent, and removing an explicit deny can take
    minutes to reach the Kafka control plane; poll until the call stops erroring."""
    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            return fn()
        except Exception as exc:  # noqa: BLE001 -- retrying any transient authz-propagation error
            last_exc = exc
            time.sleep(interval_s)
    raise AssertionError(f"call did not succeed within {timeout_s}s after granting permission: {last_exc}")


def _delete_role_policy_best_effort(iam, role_name, policy_name):
    try:
        iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _client_with_creds(ctx, service, creds):
    """A ctx client for `service` authenticated with the given temporary credentials."""
    return ctx.client(service, creds={
        "aws_access_key_id": creds["AccessKeyId"],
        "aws_secret_access_key": creds["SecretAccessKey"],
        "aws_session_token": creds["SessionToken"],
    })


def _default_vpc_subnets_sg(ctx):
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError(f"the run's shared network {ctx.network().vpc_id} is not visible")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    by_az: dict[str, str] = {}
    for s in subnets:
        by_az.setdefault(s["AvailabilityZone"], s["SubnetId"])
    subnet_ids = list(by_az.values())[:2]
    if len(subnet_ids) < 2:
        raise AssertionError("shared network does not span >=2 availability zones with subnets")
    sgs = ec2.describe_security_groups(
        Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "group-name", "Values": ["default"]}]
    )["SecurityGroups"]
    sg_id = sgs[0]["GroupId"]
    return vpc_id, subnet_ids, sg_id


def _pick_kafka_version(ctx):
    """Pick an ACTIVE Kafka version usable with a Standard broker instance type.

    The newest version is not always usable (MSK reserves some patch versions for Express
    brokers), so take versions in the order AWS lists them rather than sorting for the newest.
    """
    kafka = ctx.client("kafka")
    versions = kafka.list_kafka_versions().get("KafkaVersions", [])
    if not versions:
        raise AssertionError("no Kafka versions available from ListKafkaVersions")
    active = [v["Version"] for v in versions if v.get("Status") == "ACTIVE"]
    if "3.9.x" in active:  # recommended, still ZooKeeper; older Standard versions are refused
        return "3.9.x"
    return active[0] if active else versions[-1]["Version"]


def _create_provisioned_cluster(ctx):
    kafka = ctx.client("kafka")
    _, subnet_ids, sg_id = _default_vpc_subnets_sg(ctx)
    version = _pick_kafka_version(ctx)
    name = ctx.unique_name("sim2real-behav-kafka-")
    resp = kafka.create_cluster(
        ClusterName=name,
        KafkaVersion=version,
        NumberOfBrokerNodes=len(subnet_ids),
        BrokerNodeGroupInfo={
            "InstanceType": "kafka.t3.small",
            "ClientSubnets": subnet_ids,
            "SecurityGroups": [sg_id],
            "StorageInfo": {"EbsStorageInfo": {"VolumeSize": 1}},
        },
        Tags={"sim2real:managed": "true"},
    )
    cluster_arn = resp["ClusterArn"]
    ctx.on_cleanup(lambda: kafka.delete_cluster(ClusterArn=cluster_arn))
    _wait_cluster_active(ctx, cluster_arn)
    return cluster_arn


def _wait_cluster_active(ctx, cluster_arn, timeout_s=1800.0, interval_s=30.0):
    kafka = ctx.client("kafka")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        info = kafka.describe_cluster(ClusterArn=cluster_arn)["ClusterInfo"]
        state = info["State"]
        if state == "ACTIVE":
            return info
        if state == "FAILED":
            raise AssertionError(f"cluster {cluster_arn} entered FAILED state while provisioning")
        time.sleep(interval_s)
    raise AssertionError(f"cluster {cluster_arn} did not become ACTIVE within {timeout_s}s")


def _create_zero_permission_role(ctx):
    """Create a role whose only inline policy is an explicit deny-all, so it can do no kafka action.

    Returns (role_name, role_arn, deny_policy_name) so the deny-all can later be removed alone.
    """
    iam = ctx.client("iam")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]
    name = ctx.unique_name("sim2real-behav-zero-perm-role-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role_arn = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: _delete_role_best_effort(iam, name))

    deny_policy_name = "deny-all"
    deny_policy = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Deny", "Action": "*", "Resource": "*"}],
    }
    iam.put_role_policy(
        RoleName=name, PolicyName=deny_policy_name, PolicyDocument=json.dumps(deny_policy)
    )
    ctx.on_cleanup(lambda: _delete_role_policy_best_effort(iam, name, deny_policy_name))
    return name, role_arn, deny_policy_name


def _delete_role_best_effort(iam, role_name):
    try:
        iam.delete_role(RoleName=role_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _assume_role(ctx, role_arn):
    sts = ctx.client("sts")

    def _try_assume():
        return sts.assume_role(
            RoleArn=role_arn, RoleSessionName=_SESSION_NAME
        )["Credentials"]

    deadline = time.monotonic() + 30.0
    creds = None
    last_exc = None
    while time.monotonic() < deadline:
        try:
            creds = _try_assume()
            break
        except Exception as exc:  # role trust propagation is eventually consistent
            last_exc = exc
            time.sleep(3)
    if creds is None:
        raise AssertionError(f"could not assume zero-permission role: {last_exc}")
    return creds


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
