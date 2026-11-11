"""deploy-msk-cluster-cfn-scram-auth-enforced."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "deploy-msk-cluster-cfn-scram-auth-enforced"
GROUP = "deploy"
SERVICES = ["kafka"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A CFN-deployed provisioned MSK cluster with SASL/SCRAM as its only client authentication
    exposes only the SCRAM broker endpoint (no plaintext, no IAM) and accepts a properly
    provisioned Secrets Manager credential; Serverless clusters do not support SCRAM."""
    kafka = ctx.client("kafka")
    _, subnets, sg = _default_vpc_and_subnets(ctx)
    version = _pick_kafka_version(ctx, kafka)
    cluster_name = ctx.unique_name("sim2real-behav-kafka-")

    outputs = _deploy_cfn(
        ctx,
        _cfn_template(),
        {
            "ClusterName": cluster_name,
            "Subnet1": subnets[0],
            "Subnet2": subnets[1],
            "SecurityGroupId": sg,
            "KafkaVersion": version,
        },
        timeout_s=2400,
    )
    cluster_arn = outputs["ClusterArn"]

    info = kafka.describe_cluster_v2(ClusterArn=cluster_arn)["ClusterInfo"]
    assert info["State"] == "ACTIVE", f"expected ACTIVE, got {info['State']}"
    client_auth = info["Provisioned"]["ClientAuthentication"]
    assert client_auth["Sasl"]["Scram"]["Enabled"] is True, f"expected SASL/SCRAM enabled, got {client_auth['Sasl']['Scram']}"
    assert client_auth["Sasl"].get("Iam", {}).get("Enabled", False) is False, f"expected SASL/IAM disabled, got {client_auth['Sasl'].get('Iam')}"
    assert client_auth.get("Tls", {}).get("Enabled", False) is False, f"expected mTLS disabled, got {client_auth.get('Tls')}"

    brokers = kafka.get_bootstrap_brokers(ClusterArn=cluster_arn)
    assert brokers.get("BootstrapBrokerStringSaslScram"), "SASL/SCRAM broker string missing"
    assert not brokers.get("BootstrapBrokerString"), "plaintext broker string must not be offered"
    assert not brokers.get("BootstrapBrokerStringSaslIam"), "SASL/IAM broker string must not be offered"
    assert not brokers.get("BootstrapBrokerStringTls"), "unauthenticated TLS broker string must not be offered"

    secret_arn = _create_scram_secret(ctx, ctx.unique_name("sim2real-behav-kafka-scram-"))
    resp = kafka.batch_associate_scram_secret(ClusterArn=cluster_arn, SecretArnList=[secret_arn])
    assert resp.get("UnprocessedScramSecrets", []) == [], f"expected no unprocessed secrets, got {resp.get('UnprocessedScramSecrets')}"
    secrets = kafka.list_scram_secrets(ClusterArn=cluster_arn)["SecretArnList"]
    assert secret_arn in secrets, f"expected {secret_arn} in associated secrets, got {secrets}"




def _default_vpc_and_subnets(ctx, count=2):

    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError("no shared network VPC available to place MSK broker ENIs")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    by_az = {}
    for s in subnets:
        by_az.setdefault(s["AvailabilityZone"], s["SubnetId"])
    if len(by_az) < count:
        raise AssertionError("shared network does not span enough AZs for an MSK cluster")
    sg = ec2.describe_security_groups(
        Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "group-name", "Values": ["default"]}]
    )["SecurityGroups"][0]["GroupId"]
    return vpc_id, list(by_az.values())[:count], sg


def _pick_kafka_version(ctx, kafka):
    versions = kafka.list_kafka_versions()["KafkaVersions"]
    active = [v["Version"] for v in versions if v.get("Status") == "ACTIVE"]
    if "3.9.x" in active:  # recommended, still ZooKeeper; older Standard versions are refused
        return "3.9.x"
    return (active or [v["Version"] for v in versions])[0]


def _create_scram_secret(ctx, suffix, username="testuser", password="Testpassw0rd!123"):
    kms = ctx.client("kms")
    key_id = kms.create_key(
        Description="sim2real-behav-kafka-scram-cmk",
        Tags=[{"TagKey": "sim2real:managed", "TagValue": "true"}],
    )["KeyMetadata"]["KeyId"]
    ctx.on_cleanup(lambda: kms.schedule_key_deletion(KeyId=key_id, PendingWindowInDays=7))
    sm = ctx.client("secretsmanager")
    secret_name = f"AmazonMSK_{suffix}"
    secret = sm.create_secret(
        Name=secret_name,
        KmsKeyId=key_id,
        SecretString=json.dumps({"username": username, "password": password}),
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )
    secret_arn = secret["ARN"]
    ctx.on_cleanup(lambda: sm.delete_secret(SecretId=secret_arn, ForceDeleteWithoutRecovery=True))
    return secret_arn


def _cfn_template() -> str:
    return """
AWSTemplateFormatVersion: '2010-09-09'
Parameters:
  ClusterName:
    Type: String
  Subnet1:
    Type: String
  Subnet2:
    Type: String
  SecurityGroupId:
    Type: String
  KafkaVersion:
    Type: String
Resources:
  MSKCluster:
    Type: AWS::MSK::Cluster
    Properties:
      ClusterName: !Ref ClusterName
      KafkaVersion: !Ref KafkaVersion
      NumberOfBrokerNodes: 2
      BrokerNodeGroupInfo:
        InstanceType: kafka.t3.small
        ClientSubnets: [!Ref Subnet1, !Ref Subnet2]
        SecurityGroups: [!Ref SecurityGroupId]
        StorageInfo:
          EBSStorageInfo:
            VolumeSize: 10
      EncryptionInfo:
        EncryptionInTransit:
          ClientBroker: TLS
      ClientAuthentication:
        Sasl:
          Scram:
            Enabled: true
Outputs:
  ClusterArn:
    Value: !Ref MSKCluster
""".strip()


def _deploy_cfn(ctx, template_body, parameters, timeout_s=2400):
    cfn = ctx.client("cloudformation")
    stack_name = ctx.unique_name("sim2real-behav-kafka-")
    cfn.create_stack(
        StackName=stack_name,
        TemplateBody=template_body,
        Parameters=[{"ParameterKey": k, "ParameterValue": v} for k, v in parameters.items()],
        Capabilities=["CAPABILITY_IAM"],
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )
    ctx.on_cleanup(lambda: cfn.delete_stack(StackName=stack_name))
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        stacks = cfn.describe_stacks(StackName=stack_name)["Stacks"]
        status = stacks[0]["StackStatus"]
        if status == "CREATE_COMPLETE":
            return {o["OutputKey"]: o["OutputValue"] for o in stacks[0].get("Outputs", [])}
        if "ROLLBACK" in status or status == "CREATE_FAILED":
            raise AssertionError(f"stack {stack_name} failed to create: {status}")
        time.sleep(2)
    raise AssertionError(f"stack {stack_name} did not reach CREATE_COMPLETE within {timeout_s}s (last={status})")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
