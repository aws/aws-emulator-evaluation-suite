"""e2e-cluster-policy-cross-account-grant-then-revoke-flow."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "e2e-cluster-policy-cross-account-grant-then-revoke-flow"
GROUP = "server-side"
SERVICES = ["kafka"]


@tags("axis:happy-path", "cap:c4", "cap:c7", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A role with no kafka identity permissions is denied GetBootstrapBrokers without a cluster
    policy, succeeds once PutClusterPolicy grants it Allow, and is denied again after
    DeleteClusterPolicy, observed via calls made as that role."""
    kafka = ctx.client("kafka")
    iam = ctx.client("iam")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    subnet_ids, sg_id = _default_subnets_and_sg(ctx, count=2)
    cluster_name = ctx.unique_name("sim2real-msk-polflow-")
    create_resp = _create_cluster_with_compatible_version(
        kafka, cluster_name=cluster_name, subnet_ids=subnet_ids, sg_id=sg_id
    )
    cluster_arn = create_resp["ClusterArn"]
    ctx.on_cleanup(lambda: _delete_cluster_ignore_missing(ctx, cluster_arn))
    _wait_cluster_active(ctx, cluster_arn, timeout_s=_budget_s(ctx, 2700.0))

    # An IAM role that has NO identity-based kafka permissions at all: whether it can call
    # GetBootstrapBrokers on this cluster is therefore governed entirely by the cluster's
    # resource policy (the exact mechanism real cross-account grants rely on).
    role_name = ctx.unique_name("sim2real-msk-external-role-")
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
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    external_kafka = _poll_assume_role_client(ctx, role_arn, "kafka", timeout_s=_budget_s(ctx, 60.0))

    # 1. No cluster policy at all -> the principal has neither an identity Allow nor a
    # resource-policy Allow, so the call must be denied.
    expected_denial = (
        f"User: arn:aws:sts::{account_id}:assumed-role/{role_name}/{_SESSION_NAME} is not "
        f"authorized to perform: kafka:GetBootstrapBrokers on resource: {cluster_arn} because "
        "no identity-based policy allows the kafka:GetBootstrapBrokers action"
    )
    code, message = _poll_error(
        lambda: external_kafka.get_bootstrap_brokers(ClusterArn=cluster_arn),
        want_code="AccessDeniedException",
        timeout_s=_budget_s(ctx, 60.0),
    )
    if code != "AccessDeniedException" and _budget_spent(ctx):
        raise TimeoutError("GetBootstrapBrokers refused with AccessDeniedException before any grant: the run budget ended first; not graded")
    assert code == "AccessDeniedException", (
        f"expected AccessDeniedException with no cluster policy and no identity policy, got {code!r}"
    )
    assert message == expected_denial, f"unexpected denial message: {message!r}"

    # 2. Grant an explicit Allow to this principal via PutClusterPolicy -> the call must
    # start succeeding purely because of the resource policy.
    grant_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowExternalRoleBootstrap",
                "Effect": "Allow",
                "Principal": {"AWS": role_arn},
                "Action": "kafka:GetBootstrapBrokers",
                "Resource": cluster_arn,
            }
        ],
    }
    kafka.put_cluster_policy(ClusterArn=cluster_arn, Policy=json.dumps(grant_policy))
    fetched = json.loads(kafka.get_cluster_policy(ClusterArn=cluster_arn)["Policy"])
    assert fetched["Statement"][0]["Sid"] == "AllowExternalRoleBootstrap", (
        f"expected the just-put policy's Sid to round-trip as 'AllowExternalRoleBootstrap', "
        f"got {fetched['Statement'][0].get('Sid')!r}"
    )

    granted_ok = _poll_bool(
        lambda: _succeeds(lambda: external_kafka.get_bootstrap_brokers(ClusterArn=cluster_arn)),
        want=True,
        timeout_s=_budget_s(ctx, 90.0),
    )
    if not granted_ok and _budget_spent(ctx):
        raise TimeoutError("GetBootstrapBrokers succeeding after PutClusterPolicy: the run budget ended first; not graded")
    assert granted_ok, "GetBootstrapBrokers still failed after PutClusterPolicy granted an explicit Allow"

    # 3. Revoke via DeleteClusterPolicy -> access reverts to denied.
    kafka.delete_cluster_policy(ClusterArn=cluster_arn)
    deleted_code, deleted_message = _error(lambda: kafka.get_cluster_policy(ClusterArn=cluster_arn))
    assert deleted_code == "NotFoundException", (
        f"expected GetClusterPolicy to report NotFoundException after DeleteClusterPolicy, "
        f"got {deleted_code!r}"
    )
    assert deleted_message == "The requested resource doesn\u2019t exist.", (
        f"unexpected GetClusterPolicy message: {deleted_message!r}"
    )

    revoked_code, revoked_message = _poll_error(
        lambda: external_kafka.get_bootstrap_brokers(ClusterArn=cluster_arn),
        want_code="AccessDeniedException",
        timeout_s=_budget_s(ctx, 90.0),
    )
    if revoked_code != "AccessDeniedException" and _budget_spent(ctx):
        raise TimeoutError("GetBootstrapBrokers refused with AccessDeniedException after DeleteClusterPolicy: the run budget ended first; not graded")
    assert revoked_code == "AccessDeniedException", (
        f"GetBootstrapBrokers still succeeded after DeleteClusterPolicy revoked the grant, got {revoked_code!r}"
    )
    assert revoked_message == expected_denial, f"unexpected denial message: {revoked_message!r}"

    # Positive control: the owner's credentials, never named in the policy, can call
    # GetBootstrapBrokers throughout, isolating the deny/grant/revoke to the resource policy.
    owner_brokers = kafka.get_bootstrap_brokers(ClusterArn=cluster_arn)
    assert owner_brokers.get("BootstrapBrokerString") or owner_brokers.get("BootstrapBrokerStringTls"), (
        f"cluster owner's own credentials could not GetBootstrapBrokers, got {owner_brokers!r}"
    )


_SESSION_NAME = "sim2real-msk-check"


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _error(fn):
    """Call fn(); return (Error.Code, Error.Message). An unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        resp = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {resp}")


def _succeeds(fn) -> bool:
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError:
        return False
    return True


def _poll_error(fn, want_code: str, timeout_s: float):
    """Poll fn() until it is rejected with want_code; return (code, message) of the last attempt,
    (None, None) when the last attempt succeeded."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    last = (None, None)
    while time.monotonic() < deadline:
        try:
            fn()
            last = (None, None)
        except ClientError as e:
            last = (e.response["Error"]["Code"], e.response["Error"].get("Message"))
            if last[0] == want_code:
                return last
        time.sleep(1)
    return last


def _poll_bool(fn, want: bool, timeout_s: float) -> bool:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        if fn() == want:
            return True
        time.sleep(1)
    return False


def _poll_assume_role_client(ctx, role_arn: str, service: str, timeout_s: float):
    """Assume role_arn (retrying while trust propagates) and return a ctx.client for service,
    which keeps the target's endpoint/TLS wiring unlike a bare boto3 client."""
    sts = ctx.client("sts")
    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            creds = sts.assume_role(RoleArn=role_arn, RoleSessionName=_SESSION_NAME)[
                "Credentials"
            ]
            return ctx.client(
                service,
                creds={
                    "aws_access_key_id": creds["AccessKeyId"],
                    "aws_secret" "_access_key": creds["SecretAccessKey"],
                    "aws_session_token": creds["SessionToken"],
                },
            )
        except Exception as exc:  # noqa: BLE001 - role trust needs a few seconds to propagate
            last_exc = exc
            time.sleep(1)
    if _budget_spent(ctx):
        raise TimeoutError(f"AssumeRole {role_arn} past trust propagation: the run budget ended first; not graded")
    raise AssertionError(f"could not assume freshly-created role {role_arn}: {last_exc}")


def _default_subnets_and_sg(ctx, count: int = 2):
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError("no shared network VPC in this account/region to place MSK broker ENIs")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    by_az: dict[str, str] = {}
    for s in subnets:
        by_az.setdefault(s["AvailabilityZone"], s["SubnetId"])
    subnet_ids = list(by_az.values())[:count]
    if len(subnet_ids) < count:
        raise AssertionError(f"shared network has fewer than {count} distinct AZs with subnets")
    sgs = ec2.describe_security_groups(
        Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "group-name", "Values": ["default"]}]
    )["SecurityGroups"]
    if not sgs:
        raise AssertionError("no default security group found in the shared network")
    return subnet_ids, sgs[0]["GroupId"]


def _create_cluster_with_compatible_version(kafka, *, cluster_name: str, subnet_ids, sg_id):
    """Create on the newest ACTIVE Kafka version accepting kafka.t3.small, falling back to older
    ones: AWS rejects t3 for some KRaft versions with two different errors and no clean cutoff."""
    from botocore.exceptions import ClientError

    versions = kafka.list_kafka_versions().get("KafkaVersions", [])
    active = [v["Version"] for v in versions if v.get("Status") == "ACTIVE"]
    candidates = sorted(active or [v["Version"] for v in versions], reverse=True)
    if "3.9.x" in candidates:  # recommended, still ZooKeeper; older Standard versions are refused
        candidates.insert(0, candidates.pop(candidates.index("3.9.x")))
    if not candidates:
        raise AssertionError("ListKafkaVersions returned no usable Kafka version")

    last_err = None
    for version in candidates:
        try:
            return kafka.create_cluster_v2(
                ClusterName=cluster_name,
                Provisioned={
                    "BrokerNodeGroupInfo": {
                        "InstanceType": "kafka.t3.small",
                        "ClientSubnets": subnet_ids,
                        "SecurityGroups": [sg_id],
                    },
                    "KafkaVersion": version,
                    "NumberOfBrokerNodes": 2,
                },
                Tags={"sim2real:managed": "true"},
            )
        except ClientError as e:
            code = e.response["Error"]["Code"]
            msg = e.response["Error"].get("Message", "")
            if code == "BadRequestException" and (
                "not supported for Kafka version" in msg or "Unsupported InstanceType" in msg
            ):
                last_err = e
                continue
            raise
    raise AssertionError(
        f"no ACTIVE Kafka version among {candidates} is compatible with kafka.t3.small: {last_err}"
    )


def _wait_cluster_active(ctx, cluster_arn: str, timeout_s: float) -> None:
    kafka = ctx.client("kafka")
    deadline = time.monotonic() + timeout_s
    state = None
    while time.monotonic() < deadline:
        state = kafka.describe_cluster_v2(ClusterArn=cluster_arn)["ClusterInfo"]["State"]
        if state == "ACTIVE":
            return
        if state == "FAILED":
            raise AssertionError("cluster transitioned to FAILED while waiting for ACTIVE")
        time.sleep(2)
    if _budget_spent(ctx):
        raise TimeoutError(f"cluster {cluster_arn} reaching ACTIVE: the run budget ended first; not graded")
    raise AssertionError(f"cluster never reached ACTIVE within {timeout_s}s (last state={state})")


def _delete_cluster_ignore_missing(ctx, cluster_arn: str, timeout_s: float = 2700.0) -> None:
    """DeleteCluster is refused while the cluster is still CREATING, so a teardown that runs after
    a provisioning timeout waits for creation to settle before deleting."""
    from botocore.exceptions import ClientError

    kafka = ctx.client("kafka")
    deadline = time.monotonic() + timeout_s
    try:
        while kafka.describe_cluster_v2(ClusterArn=cluster_arn)["ClusterInfo"]["State"] == "CREATING":
            if time.monotonic() > deadline:
                raise AssertionError(f"cluster {cluster_arn} still CREATING after {timeout_s}s")
            time.sleep(2)
        kafka.delete_cluster(ClusterArn=cluster_arn)
    except ClientError as e:
        if e.response["Error"]["Code"] != "NotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
