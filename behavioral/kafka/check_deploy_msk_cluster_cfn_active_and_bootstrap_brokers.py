"""deploy-msk-cluster-cfn-active-and-bootstrap-brokers."""
from __future__ import annotations

import socket
import time

from behavioral_harness import tags

CHECK = "deploy-msk-cluster-cfn-active-and-bootstrap-brokers"
GROUP = "deploy"
SERVICES = ["kafka"]

_TEMPLATE = """
AWSTemplateFormatVersion: '2010-09-09'
Parameters:
  SubnetId1:
    Type: String
  SubnetId2:
    Type: String
  KafkaVersion:
    Type: String
Resources:
  MSKCluster:
    Type: AWS::MSK::Cluster
    Properties:
      ClusterName: !Sub '${AWS::StackName}-cluster'
      KafkaVersion: !Ref KafkaVersion
      NumberOfBrokerNodes: 2
      BrokerNodeGroupInfo:
        InstanceType: kafka.m5.large
        ClientSubnets:
          - !Ref SubnetId1
          - !Ref SubnetId2
Outputs:
  ClusterArn:
    Value: !Ref MSKCluster
"""


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:deploy", "plane:control")
def run(ctx) -> None:
    """A CloudFormation-deployed MSK cluster is itself ACTIVE (not just CREATE_COMPLETE) and
    GetBootstrapBrokers returns broker hostnames that resolve in DNS."""
    cfn = ctx.client("cloudformation")
    kafka = ctx.client("kafka")
    subnet_ids, _sg_id = _default_vpc_two_az_subnets(ctx)
    candidates = _kafka_version_candidates(kafka)

    stack_name = ctx.unique_name("sim2real-msk-cfn-")
    ctx.on_cleanup(lambda: _delete_stack_and_wait(cfn, stack_name))

    cluster_arn = None
    last_error: Exception | None = None
    for kafka_version in candidates[:4]:
        cfn.create_stack(
            StackName=stack_name,
            TemplateBody=_TEMPLATE,
            Parameters=[
                {"ParameterKey": "SubnetId1", "ParameterValue": subnet_ids[0]},
                {"ParameterKey": "SubnetId2", "ParameterValue": subnet_ids[1]},
                {"ParameterKey": "KafkaVersion", "ParameterValue": kafka_version},
            ],
            Tags=[{"Key": "sim2real:managed", "Value": "true"}],
        )
        try:
            _wait_stack_status(
                cfn, stack_name, {"CREATE_COMPLETE"}, {"ROLLBACK_COMPLETE", "CREATE_FAILED", "ROLLBACK_FAILED"}
            )
        except _KafkaVersionUnsupported as exc:
            # MSK can reserve its newest ListKafkaVersions entry for another broker category
            # ("Standard instance types are not supported for Kafka version 4.2.x.kraft"); delete
            # the rolled-back stack and retry with the next-newest candidate.
            last_error = exc
            _delete_stack_and_wait(cfn, stack_name)
            continue
        outputs = {
            o["OutputKey"]: o["OutputValue"]
            for o in cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["Outputs"]
        }
        cluster_arn = outputs["ClusterArn"]
        break
    if cluster_arn is None:
        raise AssertionError(
            f"no candidate Kafka version supports kafka.m5.large via AWS::MSK::Cluster: {last_error}"
        )

    cluster_info = kafka.describe_cluster_v2(ClusterArn=cluster_arn)["ClusterInfo"]
    assert cluster_info["State"] == "ACTIVE", f"cluster state is {cluster_info['State']!r}, not ACTIVE"

    brokers = kafka.get_bootstrap_brokers(ClusterArn=cluster_arn)
    # The template sets no EncryptionInfo, so MSK's default TLS-only client-broker encryption
    # populates BootstrapBrokerStringTls instead of the plaintext field; accept either.
    bootstrap = brokers.get("BootstrapBrokerString") or brokers.get("BootstrapBrokerStringTls")
    assert bootstrap, f"GetBootstrapBrokers returned neither a plaintext nor a TLS broker string: {brokers!r}"
    endpoints = [ep for ep in bootstrap.split(",") if ep]
    assert len(endpoints) >= 2, f"expected at least 2 broker endpoints, got {endpoints!r}"
    for endpoint in endpoints:
        host, _, port = endpoint.rpartition(":")
        assert host and port.isdigit(), f"malformed bootstrap endpoint: {endpoint!r}"
        socket.getaddrinfo(*ctx.endpoint_host(host, int(port)))  # raises socket.gaierror if the hostname is not resolvable


# ===== helpers =====
def _default_vpc_two_az_subnets(ctx):
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError("account has no shared network VPC to place the MSK cluster in")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    by_az = {}
    for s in subnets:
        by_az.setdefault(s["AvailabilityZone"], s["SubnetId"])
    if len(by_az) < 2:
        raise AssertionError("shared network does not span at least 2 Availability Zones")
    subnet_ids = list(by_az.values())[:2]
    sg_id = ec2.describe_security_groups(
        Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "group-name", "Values": ["default"]}]
    )["SecurityGroups"][0]["GroupId"]
    return subnet_ids, sg_id


class _KafkaVersionUnsupported(AssertionError):
    """Raised when a stack failed specifically because MSK rejected the KafkaVersion for this
    instance type -- distinct from any other stack failure, which must not be retried."""


def _kafka_version_candidates(kafka) -> list[str]:
    resp = kafka.list_kafka_versions()
    versions = [v["Version"] for v in resp.get("KafkaVersions", []) if v.get("Status") == "ACTIVE"]
    if not versions:
        versions = [v["Version"] for v in resp.get("KafkaVersions", [])]
    if not versions:
        raise AssertionError("ListKafkaVersions returned no versions")

    def _key(v: str):
        try:
            return tuple(int(p) for p in v.split("."))
        except ValueError:
            return (0,)

    # MSK sometimes reserves the single newest ListKafkaVersions entry for a different broker
    # category (Express) and rejects it for "Standard" instance types like kafka.m5.large; a
    # purely-numeric version sorts first here, and run() falls back through the rest on that
    # specific rejection rather than assuming the newest entry is always usable.
    return sorted(versions, key=_key, reverse=True)


def _wait_stack_status(cfn, stack_name, success_states, failure_states, timeout_s=2400.0, interval_s=20.0):
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        status = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"]
        if status in success_states:
            return status
        if status in failure_states:
            reasons = []
            try:
                for e in cfn.describe_stack_events(StackName=stack_name)["StackEvents"][:20]:
                    if "FAILED" in e.get("ResourceStatus", ""):
                        reasons.append(f"{e.get('LogicalResourceId')}: {e.get('ResourceStatusReason')}")
            except Exception:
                pass
            detail = f"stack {stack_name} entered failure state {status}; failed resources: {reasons}"
            if any("not supported for Kafka version" in r for r in reasons):
                raise _KafkaVersionUnsupported(detail)
            raise AssertionError(detail)
        time.sleep(interval_s)
    raise AssertionError(f"stack {stack_name} did not settle within {timeout_s}s, last status {status}")


def _delete_stack_and_wait(cfn, stack_name, timeout_s=1740.0, interval_s=2.0):
    """Deletes the stack and waits until it is gone, within the suite's 1800 s cleanup budget."""
    from botocore.exceptions import ClientError

    cfn.delete_stack(StackName=stack_name)
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        try:
            status = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"]
        except ClientError as exc:
            error = exc.response["Error"]
            if error["Code"] == "ValidationError" and "does not exist" in error.get("Message", ""):
                return
            raise
        if status == "DELETE_COMPLETE":
            return
        if status == "DELETE_FAILED":
            raise AssertionError(f"stack {stack_name} reached DELETE_FAILED")
        time.sleep(interval_s)
    raise AssertionError(f"stack {stack_name} was not deleted within {timeout_s}s, last status {status}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
