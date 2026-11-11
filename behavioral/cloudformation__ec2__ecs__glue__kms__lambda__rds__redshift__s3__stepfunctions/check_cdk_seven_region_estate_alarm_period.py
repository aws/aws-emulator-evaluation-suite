"""cdk-seven-region-estate-alarm-period."""
from __future__ import annotations

import base64
import json
import shutil
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from botocore.exceptions import ClientError
from fidelity_tests_runner import require_tools

from behavioral_harness import tags

CHECK = "cdk-seven-region-estate-alarm-period"
GROUP = "deploy"
SERVICES = ["appconfigdata", "autoscaling", "cloudformation", "cloudwatch", "dynamodb", "ec2",
            "ecr", "ecs", "elasticache", "elbv2", "emr", "events", "glue", "iam", "kms",
            "lakeformation", "lambda", "logs", "network-firewall", "rds", "redshift",
            "redshift-data", "s3", "secretsmanager", "sqs", "ssm", "stepfunctions", "wafv2"]

_APP = "cdk_seven_region_estate"
# --ci keeps the CLI off a TTY; --no-notices / --no-version-reporting keep it off the network.
_CDK_FLAGS = ("--ci", "--no-version-reporting", "--no-notices")

_BOOTSTRAP_TIMEOUT_S = 1200.0
_DEPLOY_TIMEOUT_S = 5400.0
_DESTROY_TIMEOUT_S = 4200.0
#: The runner's teardown budget for this suite (its heavy members' 1800 s) less a margin. Teardown
#: bounds its own waits by it: ctx.time_left() counts down the run's budget, not the teardown's.
_TEARDOWN_S = 1740.0
#: Teardown time held back from the stack deletes for the steps after them.
_AFTER_STACKS_S = 420.0
_POLL_S = 2.0

# region-pinned: the estate deploys to the regions it declares, whatever the runner's own.
_HOME = "us-east-1"
#: The app's stack parts and the region each deploys to, passed to the app as context.
# region-pinned: each stack's region as the estate declares it; every client follows this map.
_PARTS = {
    "AppRoles": _HOME, "AliasFunctions": _HOME, "FlowLogVpc": _HOME,
    "LegacyAmiInstance": "eu-west-1", "PrivateNatServer": "us-west-2",
    "TransitFirewall": "ap-northeast-2", "HelperAsg": "us-west-2", "DualVpcHelper": "us-west-2",
    "DisabledKeyAsg": "us-west-2", "FargateWebApp": _HOME, "CacheTransit": _HOME,
    "FirelensService": "us-west-2", "CrashLoopService": "us-west-2", "ClusterNlb": "us-west-2",
    "SparkCluster": "eu-west-1", "ScheduledTask": _HOME, "RoleReportJob": "us-west-2",
    "FailingStateMachine": "ap-southeast-2", "LakeFormationSettings": _HOME,
    "LakeFormationEtl": _HOME, "RedshiftClusters": _HOME, "HyperPodNlb": "us-west-2",
    "CrossAccountImage": "us-west-2", "MetadataTags": "us-west-2", "ClickstreamData": _HOME,
    "PrivateLoadBalancers": _HOME, "GpuInference": _HOME, "SecondaryEniAsg": "us-west-2",
    "DeploymentControllers": "ap-northeast-1", "AuroraPostgres": _HOME,
    "ConfigFunction": "us-west-2", "SsmDocuments": "eu-central-1",
}
_REGIONS = sorted(set(_PARTS.values()))

#: What the crash-looping container prints before it exits 1.
_MISSING_VARIABLE_LINES = [
    "ERROR Missing required environment variable: DB_PASSWORD",
    "ERROR Failed to connect to database: Connection refused",
    "ERROR Database host not reachable: garnet-db.internal",
    "ERROR Application startup failed. Exiting with code 1",
]
_VALIDATION_ERROR = "Configuration validation failed: missing required field 'targetBucket'"
_APPCONFIG_LOGICAL_IDS = ("GRNCMSAppConfigApplication537888D7",
                          "GRNCMSAppConfigEnvironment9802B737",
                          "GRNCMSAppConfigConfigurationConfigurationProfile7AB3584E")
#: The one tag the inference repository holds: busybox pinned by digest, from ECR Public's mirror
#: of the Docker official images.
_SEEDED_TAG = "dev_build_service_main"
_BUSYBOX = ("public.ecr.aws/docker/library/busybox"
            "@sha256:b7f3d86d6e84fc17718c48bcde1450807faa2d56704205c697b4bd5df7b9e29f")
#: The web app's tag, and the image it names: an Amazon Linux 2 streamlit app built with an old
#: libxml2-python, served on 8501.
_WEB_APP_TAG = "a3f1c2e4-9b7d-4e8a-b6f0-2d5c8e1a4f7b_service_main"
_WEB_APP_DOCKERFILE = """\
FROM --platform=linux/amd64 public.ecr.aws/amazonlinux/amazonlinux:2

RUN yum install -y libxml2-python-2.9.1-6.amzn2.5.18 || yum install -y libxml2-python

# gcc and python3-devel build the native wheels streamlit's dependencies need on Python 3.7.
RUN yum install -y python3 python3-pip python3-devel gcc && \\
    pip3 install --upgrade pip && \\
    pip3 install streamlit==1.23.1

WORKDIR /app

RUN echo 'import streamlit as st\\n\\
st.title("Vulnerable Application")\\n\\
st.write("This application contains vulnerable packages for security testing.")\\n\\
st.write("Package: libxml2-python 2.9.1-6.amzn2.5.18")\\n\\
' > app.py

EXPOSE 8501
CMD ["streamlit", "run", "app.py", "--server.port=8501", "--server.address=0.0.0.0"]
"""
_REFERENCED_TAG = "dev_build_service_latest"
_BASALT_SAMPLE = "data/region=us-east-1/name=devices-flint/sample.json"
_UNLISTED_OBJECT = "data/test-object.json"
#: How ECS reports a task whose essential container exited: its stop code and reason.
_ESSENTIAL_EXIT = ("EssentialContainerExited", "Essential container in task exited")
_CODE_DEPLOY_REFUSAL = ("Unable to update task definition on services with a CODE_DEPLOY "
                        "deployment controller. Use AWS CodeDeploy to trigger a new deployment.")


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:deploy",
      "concern:e2e", "concern:negative-classes", "dp:api", "dp:native", "plane:control",
      "plane:data", "resource:account-singleton:lakeformation-data-lake-settings")
def run(ctx) -> None:
    """A thirty-two-stack CDK estate in seven regions deploys, serves and destroys whole.

    Its functions, tasks, clusters, queues, keys and configuration serve, its health alarm holds its
    declared period, and each deliberately broken path is refused or fails as AWS reports it.

    Reference: https://docs.aws.amazon.com/AmazonCloudWatch/latest/APIReference/API_PutMetricAlarm.html
    """
    ctx.verify_account_safety()
    require_tools("cdk", "node", "docker")

    caller = ctx.client("sts").get_caller_identity()
    account = caller["Account"]
    qualifier = ctx.unique_name("q")[:10]
    prefix = ctx.unique_name("sim2real-tm-")
    state: dict[str, Any] = {
        "account": account,
        "qualifier": qualifier,
        "toolkit": ctx.unique_name("sim2real-cdktk-"),
        "stacks": {part: f"{prefix}-{part}" for part in _PARTS},
        "resources": {},
        "prior_lake_settings": ctx.client("lakeformation", region=_HOME).get_data_lake_settings()[
            "DataLakeSettings"],
        "kept_volumes": [],
        "retained": [],
        "local_images": [],
        "docker_config": tempfile.mkdtemp(prefix="sim2real-tm-docker-"),
    }
    ctx.on_cleanup(lambda: shutil.rmtree(state["docker_config"], ignore_errors=True))
    ctx.on_cleanup(lambda: _remove_local_images(ctx, state))
    work = _stage_app(ctx, _APP)
    # Registered before anything exists, so a run that fails anywhere still reaps all of it.
    ctx.on_cleanup(lambda: _teardown(ctx, state))

    lf_admin = _principal_arn(ctx, caller["Arn"])
    context = {
        "account": account, "prefix": prefix, "qualifier": qualifier,
        "s3-prefix-list": _s3_prefix_list(ctx, _PARTS["ClusterNlb"]),
        "lf-admin-arn": lf_admin,
        "regions": ";".join(f"{part}={region}" for part, region in _PARTS.items()),
        "azs": ";".join(f"{r}={','.join(_zones(ctx.client('ec2', region=r)))}"
                        for r in _REGIONS),
    }

    _bootstrap(ctx, state)
    try:
        _cdk(ctx, work, ["deploy", "--all", "--require-approval", "never", "--concurrency", "16",
                         "--tags", f"sim2real={CHECK}"], context, timeout_s=_DEPLOY_TIMEOUT_S)
    finally:
        _record_resources(ctx, state)
        _record_kept_volumes(ctx, state)

    # 1. every stack of the estate is CREATE_COMPLETE.
    outputs: dict[str, dict[str, str]] = {}
    for part, name in state["stacks"].items():
        stack = _cl(ctx, part, "cloudformation").describe_stacks(StackName=name)["Stacks"][0]
        assert stack["StackStatus"] == "CREATE_COMPLETE", (
            f"stack {name!r} in {_PARTS[part]} is {stack['StackStatus']!r}, expected "
            f"CREATE_COMPLETE"
        )
        outputs[part] = {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}

    _push_images(ctx, state, outputs)

    # 2. the long-running work starts first, so its waits overlap the reads below.
    glue_run = _start_governed_job(ctx, outputs["LakeFormationEtl"])
    execution = _cl(ctx, "FailingStateMachine", "stepfunctions").start_execution(
        stateMachineArn=outputs["FailingStateMachine"]["StateMachineArn"],
        input=json.dumps({"source": "deploy"}))["executionArn"]
    crash_task = _start_crash_task(ctx, outputs["CrashLoopService"])
    emr_step = _start_emr_step(ctx, outputs["SparkCluster"])

    # 3. the estate serves, and its broken paths fail as AWS reports them.
    _assert_app_roles_and_lake_settings(ctx, state, lf_admin)
    _assert_service_roles(ctx, state, outputs)
    _assert_alias_serves_and_absent_version_refused(ctx, outputs["AliasFunctions"])
    _assert_single_flow_log(ctx, state, outputs["FlowLogVpc"])
    _assert_instances(ctx, state, outputs)
    _assert_secrets_and_missing_decrypt(ctx, outputs)
    _assert_disabled_key_refused(ctx, outputs["DisabledKeyAsg"])
    _assert_transit_routes_and_firewalls(ctx, outputs)
    _assert_cache_and_running_tasks(ctx, outputs["CacheTransit"])
    _assert_load_balancers_internal(ctx, outputs)
    _assert_code_deploy_service_refuses_task_definition(ctx, outputs["DeploymentControllers"])
    _assert_idle_services_and_schedules(ctx, outputs)
    _assert_web_app_image(ctx, outputs["FargateWebApp"])
    _assert_inference_tag_absent(ctx, state, outputs["GpuInference"])
    _assert_appconfig_ids_refused_and_function_falls_back(ctx, outputs["ConfigFunction"])
    _assert_clickstream_reads_and_queue(ctx, state, outputs["ClickstreamData"])
    _assert_ssm_documents(ctx, outputs["SsmDocuments"])
    _assert_aurora(ctx, outputs["AuroraPostgres"])
    _assert_state_machine_failed(ctx, outputs["FailingStateMachine"], execution)
    _assert_crash_task_exited(ctx, outputs["CrashLoopService"], crash_task)
    _assert_governed_job_refused(ctx, outputs["LakeFormationEtl"], glue_run)
    _assert_emr_step_and_configuration(ctx, outputs["SparkCluster"], emr_step)
    _assert_redshift_serves_and_health_alarm_period(ctx, outputs["RedshiftClusters"])

    # 4. destroy removes every stack and what each owns, except what the app retains.
    _record_retained(ctx, state)
    _cdk(ctx, work, ["destroy", "--all", "--force", "--concurrency", "16"], context,
         timeout_s=_DESTROY_TIMEOUT_S)
    for part, name in state["stacks"].items():
        gone = _error(f"DescribeStacks on destroyed stack {name}",
                      lambda part=part, name=name: _cl(ctx, part, "cloudformation")
                      .describe_stacks(StackName=name))
        assert gone == ("ValidationError", f"Stack with id {name} does not exist"), (
            f"after `cdk destroy --all`, DescribeStacks on {name!r} returned {gone!r}"
        )
    _assert_owned_resources_gone(ctx, outputs)
    _assert_retained_outlive_destroy(ctx, state)


def _cl(ctx, part: str, service: str):
    """The client for ``service`` in the region of stack ``part``."""
    return ctx.client(service, region=_PARTS[part])


def _prefix(state) -> str:
    """The run's name prefix, which every stack id and physical name starts with."""
    return state["stacks"]["AppRoles"].removesuffix("-AppRoles")


def _role_holds(iam, role: str) -> dict:
    """``role``'s trust principals, AWS and customer managed policy names, and inline count."""
    statements = iam.get_role(RoleName=role)["Role"]["AssumeRolePolicyDocument"]["Statement"]
    arns = [entry["PolicyArn"]
            for listing in iam.get_paginator("list_attached_role_policies").paginate(RoleName=role)
            for entry in listing["AttachedPolicies"]]
    return {"trust": [statement["Principal"] for statement in statements],
            "aws": sorted(a.rsplit("/", 1)[1] for a in arns if ":iam::aws:policy/" in a),
            "customer": sorted(a.rsplit("/", 1)[1] for a in arns if ":iam::aws:policy/" not in a),
            "inline": len(iam.list_role_policies(RoleName=role)["PolicyNames"])}


def _holding(trust: dict, aws=(), customer=(), inline: int = 0) -> dict:
    """What ``_role_holds`` reads for a role trusting ``trust`` and holding the given policies."""
    return {"trust": [trust], "aws": sorted(aws), "customer": sorted(customer), "inline": inline}


def _assert_app_roles_and_lake_settings(ctx, state, lf_admin: str) -> None:
    """The app roles read only and Bedrock's role holds nothing; the data lake admins are the
    stack's, with no default grant to IAMAllowedPrincipals."""
    iam = ctx.client("iam")
    prefix, root = _prefix(state), {"AWS": f"arn:aws:iam::{state['account']}:root"}
    want = {
        f"{prefix}-app-readonly": _holding(
            root, aws=("AmazonS3TablesReadOnlyAccess", "ReadOnlyAccess"),
            customer=(f"{prefix}-s3vectors-ro",)),
        f"{prefix}-app-operator": _holding(root, aws=("ReadOnlyAccess",)),
        f"{prefix}-app-bedrock": _holding({"Service": "bedrock.amazonaws.com"}),
    }
    roles = sorted(r for t, r, _ in state["resources"].get("AppRoles", [])
                   if t == "AWS::IAM::Role")
    assert roles == sorted(want), f"AppRoles holds roles {roles!r}, expected {sorted(want)!r}"
    for role, expected in want.items():
        held = _role_holds(iam, role)
        assert held == expected, f"role {role!r} trusts and holds {held!r}, expected {expected!r}"
    operator = iam.get_role(RoleName=f"{prefix}-app-operator")["Role"]["Arn"]
    results = iam.simulate_principal_policy(
        PolicySourceArn=operator, ActionNames=["iam:CreateUser", "s3:ListAllMyBuckets"])
    decisions = {r["EvalActionName"]: r["EvalDecision"] for r in results["EvaluationResults"]}
    assert decisions == {"iam:CreateUser": "implicitDeny", "s3:ListAllMyBuckets": "allowed"}, (
        f"the operator role evaluates to {decisions!r}"
    )
    settings = ctx.client("lakeformation", region=_HOME).get_data_lake_settings()[
        "DataLakeSettings"]
    admins = {a["DataLakePrincipalIdentifier"] for a in settings.get("DataLakeAdmins", [])}
    exec_role = (f"arn:aws:iam::{state['account']}:role/cdk-{state['qualifier']}-cfn-exec-role-"
                 f"{state['account']}-{_HOME}")
    assert admins == {exec_role, lf_admin}, f"the data lake admins are {sorted(admins)!r}"
    # The stack's empty default-permission lists leave the account's defaults as they were.
    prior = state["prior_lake_settings"]
    for key in ("CreateTableDefaultPermissions", "CreateDatabaseDefaultPermissions"):
        assert settings.get(key, []) == prior.get(key, []), (
            f"{key} is {settings.get(key)!r}, but was {prior.get(key)!r} before the deploy"
        )


def _assert_service_roles(ctx, state, outputs) -> None:
    """The roles nothing assumes trust only their service and hold nothing; the external readers'
    role reads the account; the governed job's role reads its script and data location only."""
    iam = ctx.client("iam")
    prefix, root = _prefix(state), {"AWS": f"arn:aws:iam::{state['account']}:root"}
    glue_role = outputs["LakeFormationEtl"]["GlueServiceRoleArn"].rsplit("/", 1)[1]
    want = {
        f"{prefix}-quartz-workhorse": _holding({"Service": "elasticmapreduce.amazonaws.com"}),
        f"{prefix}-operations-access": _holding({"Service": "ec2.amazonaws.com"}),
        f"{prefix}-external-access": _holding(root, aws=("ReadOnlyAccess",), inline=1),
        glue_role: _holding({"Service": "glue.amazonaws.com"},
                            aws=("AWSGlueServiceRole", "AWSLakeFormationDataAdmin"), inline=1),
    }
    for role, expected in want.items():
        held = _role_holds(iam, role)
        assert held == expected, f"role {role!r} trusts and holds {held!r}, expected {expected!r}"


def _assert_alias_serves_and_absent_version_refused(ctx, out) -> None:
    """The LATEST alias runs its published version; moving it to an absent version is refused."""
    lam = _cl(ctx, "AliasFunctions", "lambda")
    function = out["SimpleEmailServiceLambdaName"]
    alias = lam.get_alias(FunctionName=function, Name="LATEST")
    assert alias["FunctionVersion"] != "$LATEST", f"alias LATEST points at {alias!r}"
    result = lam.invoke(FunctionName=function, Qualifier="LATEST", Payload=b"{}")
    assert "FunctionError" not in result and result["ExecutedVersion"] == alias[
        "FunctionVersion"], (
        f"{function}:LATEST ran {result['ExecutedVersion']!r} with "
        f"FunctionError={result.get('FunctionError')!r}, expected {alias['FunctionVersion']!r}"
    )
    body = json.loads(result["Payload"].read())
    assert body == {"statusCode": 200, "body": "success"}, f"the alias returned {body!r}"

    refused = _error("UpdateAlias to version 593",
                     lambda: lam.update_alias(FunctionName=function, Name="LATEST",
                                              FunctionVersion="593"))
    expected = ("ResourceNotFoundException",
                f"Function not found: {out['SimpleEmailServiceLambdaArn']}:593")
    assert refused == expected, f"UpdateAlias to an absent version returned {refused!r}"
    after = lam.get_alias(FunctionName=function, Name="LATEST")["FunctionVersion"]
    assert after == alias["FunctionVersion"], f"the refused update moved the alias to {after!r}"


def _assert_single_flow_log(ctx, state, out) -> None:
    """The VPC's one flow log delivers to its bucket; the two log groups receive none."""
    ec2 = _cl(ctx, "FlowLogVpc", "ec2")
    logs = _cl(ctx, "FlowLogVpc", "logs")
    flows = ec2.describe_flow_logs(Filters=[{"Name": "resource-id",
                                             "Values": [out["VpcId"]]}])["FlowLogs"]
    assert [f["FlowLogId"] for f in flows] == [out["FlowLogId"]], flows
    flow = flows[0]
    assert (flow["LogDestinationType"], flow["LogDestination"], flow["FlowLogStatus"],
            flow["TrafficType"]) == ("s3", f"arn:aws:s3:::{out['VpcFlowLogsBucketName']}",
                                     "ACTIVE", "ALL"), flow
    orphans = _physical_ids(state, "FlowLogVpc", "AWS::Logs::LogGroup")
    assert len(orphans) == 2, f"the stack's log groups are {orphans!r}"
    for group in orphans:
        found = logs.describe_log_groups(logGroupNamePrefix=group)["logGroups"]
        assert [g["logGroupName"] for g in found] == [group], found
        writing = ec2.describe_flow_logs(Filters=[{"Name": "log-group-name",
                                                   "Values": [group]}])["FlowLogs"]
        assert writing == [], f"log group {group!r} has flow logs {writing!r}"


def _instance(ec2, instance_id: str) -> dict:
    """The description of one instance."""
    return ec2.describe_instances(InstanceIds=[instance_id])["Reservations"][0]["Instances"][0]


def _assert_instances(ctx, state, outputs) -> None:
    """Each instance runs with its metadata options, interfaces and volumes as declared."""
    legacy = _instance(_cl(ctx, "LegacyAmiInstance", "ec2"),
                       outputs["LegacyAmiInstance"]["EC2InstanceId"])
    assert (legacy["State"]["Name"], legacy["ImageId"], legacy["MetadataOptions"]["HttpTokens"],
            "PublicIpAddress" in legacy) == (
        "running", outputs["LegacyAmiInstance"]["EC2AmiId"], "required", False), legacy
    image = _cl(ctx, "LegacyAmiInstance", "ec2").describe_images(
        ImageIds=[legacy["ImageId"]])["Images"][0]
    assert image["Name"].startswith("amzn2-ami-"), f"the instance runs image {image['Name']!r}"

    tags_ec2 = _cl(ctx, "MetadataTags", "ec2")
    out = outputs["MetadataTags"]
    options = {key: _instance(tags_ec2, out[key])["MetadataOptions"]
               for key in ("InstanceId", "OtherInstance1Id", "OtherInstance2Id")}
    assert [o["InstanceMetadataTags"] for o in options.values()] == [
        "enabled", "disabled", "disabled"], options
    assert [o["HttpTokens"] for o in options.values()] == ["required"] * 3, options
    assert options["OtherInstance2Id"]["HttpPutResponseHopLimit"] == 3, options

    nat_ec2 = _cl(ctx, "PrivateNatServer", "ec2")
    out = outputs["PrivateNatServer"]
    server = _instance(nat_ec2, out["InstanceId"])
    assert server["SubnetId"] == out["PrivateSubnetId"] and "PublicIpAddress" not in server, server
    assert {g["GroupId"] for g in server["SecurityGroups"]} == {
        out["AppServerSecurityGroupId"], out["SshSecurityGroupId"]}, server["SecurityGroups"]
    devices = {m["DeviceName"]: m["Ebs"] for m in server["BlockDeviceMappings"]}
    assert devices["/dev/sdf"]["DeleteOnTermination"] is False, devices
    assert state["kept_volumes"] == [devices["/dev/sdf"]["VolumeId"]], state["kept_volumes"]
    nat = nat_ec2.describe_nat_gateways(NatGatewayIds=[out["NatGatewayId"]])["NatGateways"][0]
    assert nat["State"] == "available", nat
    routes = nat_ec2.describe_route_tables(RouteTableIds=[out["RouteTableId"]])["RouteTables"][0]
    defaults = [r.get("NatGatewayId") for r in routes["Routes"]
                if r.get("DestinationCidrBlock") == "0.0.0.0/0"]
    assert defaults == [out["NatGatewayId"]], routes["Routes"]

    dual_ec2 = _cl(ctx, "DualVpcHelper", "ec2")
    out = outputs["DualVpcHelper"]
    helper = _instance(dual_ec2, out["InstanceId"])
    by_index = {n["Attachment"]["DeviceIndex"]: n for n in helper["NetworkInterfaces"]}
    assert sorted(by_index) == [0, 1], helper["NetworkInterfaces"]
    second = by_index[1]
    assert (second["NetworkInterfaceId"], second["VpcId"],
            second["Attachment"]["DeleteOnTermination"]) == (
        out["SecondaryNetworkInterfaceId"], out["CustomerVpcId"], False), second
    assert "Association" not in by_index[0], f"the helper has a public address: {by_index[0]!r}"


def _simulate(iam, role_arn: str, action: str, resource: str) -> str:
    """IAM's decision for ``role_arn`` calling ``action`` on ``resource``."""
    result = iam.simulate_principal_policy(PolicySourceArn=role_arn, ActionNames=[action],
                                           ResourceArns=[resource])
    return result["EvaluationResults"][0]["EvalDecision"]


def _assert_secrets_and_missing_decrypt(ctx, outputs) -> None:
    """Both helper secrets read back; one role may decrypt its key, the other may not."""
    iam = ctx.client("iam")
    dual = outputs["DualVpcHelper"]
    secret = json.loads(_cl(ctx, "DualVpcHelper", "secretsmanager").get_secret_value(
        SecretId=dual["SecretArn"])["SecretString"])
    assert (secret["certificate"], secret["privateKey"]) == (
        "placeholder-certificate-data", "placeholder-private-key-data"), sorted(secret)
    assert _simulate(iam, dual["InstanceRoleArn"], "secretsmanager:GetSecretValue",
                     dual["SecretArn"]) == "allowed"
    assert _simulate(iam, dual["InstanceRoleArn"], "kms:Decrypt",
                     dual["KmsKeyArn"]) == "implicitDeny", (
        "the helper role must lack kms:Decrypt on the secret's key"
    )
    eni = outputs["SecondaryEniAsg"]
    other = json.loads(_cl(ctx, "SecondaryEniAsg", "secretsmanager").get_secret_value(
        SecretId=eni["QuartzSecretArn"])["SecretString"])
    assert other["certificate"] == "PLACEHOLDER_CERTIFICATE", sorted(other)
    key_arn = _cl(ctx, "SecondaryEniAsg", "kms").describe_key(KeyId=eni["KmsKeyId"])[
        "KeyMetadata"]["Arn"]
    assert _simulate(iam, eni["InstanceRoleArn"], "kms:Decrypt", key_arn) == "allowed"
    acl = _cl(ctx, "SecondaryEniAsg", "ec2").describe_network_acls(
        NetworkAclIds=[eni["PrivateSubnetNaclId"]])["NetworkAcls"][0]
    deny = [e for e in acl["Entries"] if e["RuleNumber"] == 50 and not e["Egress"]]
    assert [(e["RuleAction"], e["PortRange"]) for e in deny] == [
        ("deny", {"From": 22, "To": 22})], acl["Entries"]


def _assert_disabled_key_refused(ctx, out) -> None:
    """The launch template's volume key is disabled, and KMS refuses to use it."""
    kms = _cl(ctx, "DisabledKeyAsg", "kms")
    key = kms.describe_key(KeyId=out["KmsKeyArn"])["KeyMetadata"]
    assert (key["KeyState"], key["Enabled"]) == ("Disabled", False), key
    refused = _error("GenerateDataKey on the disabled key",
                     lambda: kms.generate_data_key(KeyId=out["KmsKeyArn"], KeySpec="AES_256"))
    assert refused == ("DisabledException", f"{out['KmsKeyArn']} is disabled."), refused
    version = _cl(ctx, "DisabledKeyAsg", "ec2").describe_launch_template_versions(
        LaunchTemplateId=out["LaunchTemplateId"], Versions=["$Latest"])[
        "LaunchTemplateVersions"][0]["LaunchTemplateData"]
    ebs = version["BlockDeviceMappings"][0]["Ebs"]
    assert (ebs["Encrypted"], ebs["KmsKeyId"]) == (True, out["KmsKeyArn"]), ebs
    assert version["MetadataOptions"]["HttpTokens"] == "required", version["MetadataOptions"]
    group = _cl(ctx, "DisabledKeyAsg", "autoscaling").describe_auto_scaling_groups(
        AutoScalingGroupNames=[out["AutoScalingGroupName"]])["AutoScalingGroups"][0]
    assert (group["DesiredCapacity"], group["Instances"]) == (0, []), group


def _static_routes(ec2, route_table: str) -> set[tuple[str, str, str]]:
    """The active routes of a transit gateway route table: ``(cidr, type, attachment)``."""
    routes = ec2.search_transit_gateway_routes(
        TransitGatewayRouteTableId=route_table,
        Filters=[{"Name": "state", "Values": ["active"]}])["Routes"]
    return {(r["DestinationCidrBlock"], r["Type"],
             r["TransitGatewayAttachments"][0]["TransitGatewayAttachmentId"]) for r in routes}


def _assert_transit_routes_and_firewalls(ctx, outputs) -> None:
    """Both transit gateways route as declared; both DMZ firewalls are ready in both subnets."""
    out = outputs["TransitFirewall"]
    ec2 = _cl(ctx, "TransitFirewall", "ec2")
    expected = {("0.0.0.0/0", "static", out["DMZVPCAttachmentId"]),
                ("10.1.0.0/16", "static", out["WorkloadVPCAttachmentId"]),
                ("10.2.0.0/16", "static", out["DMZVPCAttachmentId"]),
                ("10.3.0.0/16", "static", out["AdditionalVPC1AttachmentId"])}
    routes = _poll_until(ctx, lambda: _static_routes(ec2, out["TGWRouteTableId"]),
                         lambda r: r == expected, timeout_s=300.0,
                         description="the transit gateway's static routes")
    assert routes == expected, f"the transit routes are {sorted(routes)!r}"
    firewall = _cl(ctx, "TransitFirewall", "network-firewall")
    for key in ("OutboundFirewallArn", "InboundFirewallArn"):
        status = _poll_until(
            ctx, lambda key=key: firewall.describe_firewall(FirewallArn=out[key])[
                "FirewallStatus"],
            lambda s: s["Status"] == "READY", timeout_s=900.0,
            description=f"firewall {out[key]} to be READY")
        assert status["Status"] == "READY", status
        attachments = [z["Attachment"] for z in status.get("SyncStates", {}).values()]
        assert sorted(a["SubnetId"] for a in attachments) == sorted(
            [out["DMZSubnetAId"], out["DMZSubnetBId"]]), status
        assert {a["Status"] for a in attachments} == {"READY"}, status

    cache = outputs["CacheTransit"]
    cache_ec2 = _cl(ctx, "CacheTransit", "ec2")
    expected = {("10.137.0.0/24", "static", cache["CacheVpcTgwAttachmentId"]),
                ("10.131.0.0/16", "propagated", cache["EcsVpcTgwAttachmentId"])}
    routes = _poll_until(ctx, lambda: _static_routes(cache_ec2, cache["EcsClientTgwRouteTableId"]),
                         lambda r: r == expected, timeout_s=300.0,
                         description="the client route table's routes")
    assert routes == expected, f"the client route table holds {sorted(routes)!r}"


def _assert_cache_and_running_tasks(ctx, out) -> None:
    """The Memcached cluster is available with in-transit encryption, and six tasks run."""
    cache = _cl(ctx, "CacheTransit", "elasticache").describe_cache_clusters(
        CacheClusterId=out["ElastiCacheClusterId"])["CacheClusters"][0]
    assert (cache["CacheClusterStatus"], cache["Engine"], cache["EngineVersion"],
            cache["TransitEncryptionEnabled"]) == ("available", "memcached", "1.6.12", True), cache
    ecs = _cl(ctx, "CacheTransit", "ecs")
    service = _poll_until(
        ctx, lambda: ecs.describe_services(cluster=out["EcsClusterName"],
                                           services=[out["EcsServiceArn"]])["services"][0],
        lambda s: s["runningCount"] == s["desiredCount"] == 6, timeout_s=600.0,
        description="the service to run six tasks")
    assert service["runningCount"] == service["desiredCount"] == 6, (
        f"the service runs {service['runningCount']!r} of {service['desiredCount']!r} tasks"
    )


def _load_balancer(elbv2, arn: str) -> dict:
    """The description of one load balancer."""
    return elbv2.describe_load_balancers(LoadBalancerArns=[arn])["LoadBalancers"][0]


def _assert_load_balancers_internal(ctx, outputs) -> None:
    """Every load balancer is internal and active; the web ALB carries its regional web ACL."""
    targets = [("PrivateLoadBalancers", outputs["PrivateLoadBalancers"]["AlbArn"]),
               ("PrivateLoadBalancers", outputs["PrivateLoadBalancers"]["NlbArn"]),
               ("FargateWebApp", outputs["FargateWebApp"]["AlbArn"]),
               ("DeploymentControllers", outputs["DeploymentControllers"]["AlbArn"]),
               ("ClusterNlb", outputs["ClusterNlb"]["NLBArn"]),
               ("HyperPodNlb", outputs["HyperPodNlb"]["NetworkLoadBalancerArn"])]
    for part, arn in targets:
        elbv2 = _cl(ctx, part, "elbv2")
        lb = _poll_until(ctx, lambda elbv2=elbv2, arn=arn: _load_balancer(elbv2, arn),
                         lambda b: b["State"]["Code"] != "provisioning", timeout_s=300.0,
                         description=f"load balancer {arn} to leave provisioning")
        assert (lb["Scheme"], lb["State"]["Code"]) == ("internal", "active"), lb
    acl = _cl(ctx, "FargateWebApp", "wafv2").get_web_acl_for_resource(
        ResourceArn=outputs["FargateWebApp"]["AlbArn"])["WebACL"]
    assert acl["ARN"] == outputs["FargateWebApp"]["WebAclArn"], acl

    # The cluster NLB checks port 4000, which its instances' group admits from nothing but
    # itself, and only on these three rules.
    out = outputs["ClusterNlb"]
    gid = out["SecurityGroupId"]
    group = _cl(ctx, "ClusterNlb", "ec2").describe_security_groups(GroupIds=[gid])[
        "SecurityGroups"][0]
    rules = sorted((p["IpProtocol"], p.get("FromPort"), p.get("ToPort"),
                    tuple(sorted(g["GroupId"] for g in p.get("UserIdGroupPairs", []))),
                    bool(p.get("IpRanges") or p.get("Ipv6Ranges") or p.get("PrefixListIds")))
                   for p in group["IpPermissions"])
    expected = sorted([("-1", None, None, (gid,), False), ("tcp", 988, 988, (gid,), False),
                       ("tcp", 1018, 1023, (gid,), False)])
    assert rules == expected, f"the cluster group admits {group['IpPermissions']!r}"
    health = _cl(ctx, "ClusterNlb", "elbv2").describe_target_groups(
        TargetGroupArns=[out["TargetGroupArn"]])["TargetGroups"][0]
    assert (health["HealthCheckProtocol"], health["HealthCheckPort"],
            health["HealthCheckPath"]) == ("HTTP", "4000", "/health-check"), health


def _assert_code_deploy_service_refuses_task_definition(ctx, out) -> None:
    """A CODE_DEPLOY service refuses a task definition update through ECS."""
    ecs = _cl(ctx, "DeploymentControllers", "ecs")
    services = ecs.describe_services(cluster=out["ClusterName"], services=[
        out["RollingServiceArn"], out["BlueGreenServiceArn"]])["services"]
    controllers = {s["serviceArn"]: s["deploymentController"]["type"] for s in services}
    assert controllers == {out["RollingServiceArn"]: "ECS",
                           out["BlueGreenServiceArn"]: "CODE_DEPLOY"}, controllers
    refused = _error("UpdateService on the CODE_DEPLOY service",
                     lambda: ecs.update_service(cluster=out["ClusterName"],
                                                service=out["BlueGreenServiceArn"],
                                                taskDefinition=out["RollingTaskDefinitionArn"]))
    assert refused == ("InvalidParameterException", _CODE_DEPLOY_REFUSAL), refused


def _assert_idle_services_and_schedules(ctx, outputs) -> None:
    """The idle services and groups hold no capacity; the schedule and the jobs are as declared."""
    for part, cluster_key, service_key in (("FargateWebApp", "ECSClusterName",
                                            "FargateServiceName"),
                                           ("FirelensService", "EcsClusterName", "EcsServiceName"),
                                           ("CrossAccountImage", "ClusterName", "ServiceName"),
                                           ("GpuInference", "AppClusterName", "ServiceName")):
        service = _cl(ctx, part, "ecs").describe_services(
            cluster=outputs[part][cluster_key], services=[outputs[part][service_key]])[
            "services"][0]
        assert (service["status"], service["desiredCount"], service["runningCount"]) == (
            "ACTIVE", 0, 0), f"{part} service is {service['status']!r} with " \
                             f"{service['runningCount']!r}/{service['desiredCount']!r}"
    for part, key in (("HelperAsg", "AutoScalingGroupName"), ("ClusterNlb", "ASGName"),
                      ("HyperPodNlb", "AutoScalingGroupName"),
                      ("SecondaryEniAsg", "AutoScalingGroupName")):
        group = _cl(ctx, part, "autoscaling").describe_auto_scaling_groups(
            AutoScalingGroupNames=[outputs[part][key]])["AutoScalingGroups"][0]
        assert (group["DesiredCapacity"], group["Instances"]) == (0, []), (part, group)
    images = [c["image"] for c in _cl(ctx, "CrossAccountImage", "ecs").describe_task_definition(
        taskDefinition=outputs["CrossAccountImage"]["TaskDefinitionArn"])["taskDefinition"][
        "containerDefinitions"]]
    assert images and all(i.startswith("123456789012.dkr.ecr.") for i in images), images

    events = _cl(ctx, "ScheduledTask", "events")
    out = outputs["ScheduledTask"]
    rule = events.describe_rule(Name=out["EventBridgeRuleName"])
    assert (rule["State"], rule["ScheduleExpression"]) == ("ENABLED", "cron(05 23 27 * ? *)"), rule
    targets = events.list_targets_by_rule(Rule=out["EventBridgeRuleName"])["Targets"]
    assert len(targets) == 1 and targets[0]["Arn"] == out["EcsClusterArn"], targets
    ecs_params = targets[0]["EcsParameters"]
    assert (ecs_params["TaskDefinitionArn"], ecs_params["LaunchType"],
            ecs_params["NetworkConfiguration"]["awsvpcConfiguration"]["AssignPublicIp"]) == (
        out["TaskDefinitionArn"], "FARGATE", "DISABLED"), ecs_params

    job = _cl(ctx, "RoleReportJob", "glue").get_job(
        JobName=outputs["RoleReportJob"]["GlueJobName"])["Job"]
    script = job["Command"]["ScriptLocation"]
    bucket, key = script.removeprefix("s3://").split("/", 1)
    assert bucket == outputs["RoleReportJob"]["GlueAssetsBucketName"], script
    missing = _error("HeadObject on the job's script",
                     lambda: _cl(ctx, "RoleReportJob", "s3").head_object(Bucket=bucket, Key=key))
    assert missing[0] == "404", f"the job's script {script!r} answered {missing!r}"


def _docker_env(ctx, state) -> dict[str, str]:
    """The subprocess environment with a Docker config of the run's own, never the host's."""
    return {**ctx.subprocess_env(), "DOCKER_CONFIG": state["docker_config"]}


def _docker(ctx, state, args: list[str], what: str, *, cwd: Path | None = None,
            stdin: str | None = None, timeout_s: float = 600.0) -> None:
    """Run one docker command under the run budget; asserts it exits 0."""
    try:
        result = subprocess.run(["docker", *args], cwd=cwd, env=_docker_env(ctx, state),
                                input=stdin, capture_output=True, text=True,
                                timeout=_budget_s(ctx, timeout_s))
    except subprocess.TimeoutExpired:
        _raise_if_budget_spent(ctx, what)
        raise
    assert result.returncode == 0, (
        f"{what} exited {result.returncode}; output tail: "
        f"{(result.stdout + result.stderr)[-1500:]!r}"
    )


def _docker_login(ctx, state, part: str) -> str:
    """Log docker in to the registry of ``part``'s region, as the target serves it; its host."""
    token = _cl(ctx, part, "ecr").get_authorization_token()["authorizationData"][0]
    user, password = base64.b64decode(token["authorizationToken"]).decode().split(":", 1)
    host = urlsplit(ctx.endpoint_url(token["proxyEndpoint"])).netloc
    _docker(ctx, state, ["login", "--username", user, "--password-stdin", host],
            f"docker login for {part}", stdin=password)
    return host


def _push_images(ctx, state, outputs) -> None:
    """Build and push the web app's image, and push busybox as the inference repository's only
    tag, as the estate is served."""
    web_host = _docker_login(ctx, state, "FargateWebApp")
    web = f"{web_host}/{outputs['FargateWebApp']['ECRRepositoryName']}:{_WEB_APP_TAG}"
    inference_host = _docker_login(ctx, state, "GpuInference")
    inference = f"{inference_host}/{outputs['GpuInference']['EcrRepositoryName']}:{_SEEDED_TAG}"
    state["local_images"] += [web, inference, _BUSYBOX]
    build = Path(tempfile.mkdtemp(prefix="sim2real-tm-image-"))
    ctx.on_cleanup(lambda: shutil.rmtree(build, ignore_errors=True))
    (build / "Dockerfile").write_text(_WEB_APP_DOCKERFILE)
    _docker(ctx, state, ["build", "-t", web, "."], "docker build of the web app image",
            cwd=build, timeout_s=1500.0)
    _docker(ctx, state, ["push", web], "docker push of the web app image", timeout_s=900.0)
    _docker(ctx, state, ["pull", _BUSYBOX], "docker pull of busybox")
    _docker(ctx, state, ["tag", _BUSYBOX, inference], "docker tag of busybox")
    _docker(ctx, state, ["push", inference], "docker push of the inference image")


def _remove_local_images(ctx, state) -> None:
    """Remove each image the run built, tagged or pulled from the host; an absent one is fine."""
    failures = []
    for image in state["local_images"]:
        result = subprocess.run(["docker", "rmi", "-f", image], env=_docker_env(ctx, state),
                                capture_output=True, text=True, timeout=300)
        if result.returncode != 0 and "No such image" not in result.stderr:
            failures.append(f"{image}: {result.stderr[-300:]!r}")
    if failures:
        raise AssertionError(f"docker rmi failed for {failures!r}")


def _assert_web_app_image(ctx, out) -> None:
    """The web app's repository holds the tag its task definition names."""
    ecr = _cl(ctx, "FargateWebApp", "ecr")
    images = ecr.describe_images(repositoryName=out["ECRRepositoryName"],
                                 imageIds=[{"imageTag": _WEB_APP_TAG}])["imageDetails"]
    assert [d["imageTags"] for d in images] == [[_WEB_APP_TAG]], images
    task = _cl(ctx, "FargateWebApp", "ecs").describe_task_definition(
        taskDefinition=out["TaskDefinitionFamily"])["taskDefinition"]
    assert [c["image"] for c in task["containerDefinitions"]] == [
        f"{out['ECRRepositoryUri']}:{_WEB_APP_TAG}"], task["containerDefinitions"]


def _assert_inference_tag_absent(ctx, state, out) -> None:
    """The repository holds only the tag pushed to it; the tag the task needs is absent."""
    ecr = _cl(ctx, "GpuInference", "ecr")
    repository = out["EcrRepositoryName"]
    listed = _poll_until(
        ctx, lambda: sorted(i.get("imageTag", "") for i in ecr.list_images(
            repositoryName=repository)["imageIds"]),
        lambda t: t == [_SEEDED_TAG], timeout_s=60.0, description="the pushed tag to list")
    assert listed == [_SEEDED_TAG], f"repository {repository!r} lists tags {listed!r}"
    images = {c["name"]: c["image"] for c in _cl(ctx, "GpuInference", "ecs")
              .describe_task_definition(taskDefinition=out["TaskDefinitionArn"])[
                  "taskDefinition"]["containerDefinitions"]}
    assert images["Container"] == f"{out['EcrRepositoryUri']}:{_REFERENCED_TAG}", images
    refused = _error(f"DescribeImages for tag {_REFERENCED_TAG}",
                     lambda: ecr.describe_images(repositoryName=repository,
                                                 imageIds=[{"imageTag": _REFERENCED_TAG}]))
    expected = (f"The image with imageId {{imageDigest:'null', imageTag:'{_REFERENCED_TAG}'}} "
                f"does not exist within the repository with name '{repository}' in the "
                f"registry with id '{state['account']}'")
    assert refused == ("ImageNotFoundException", expected), refused


def _assert_appconfig_ids_refused_and_function_falls_back(ctx, out) -> None:
    """Logical ids are refused by the data plane, the real ids serve the deployed content, and
    the function holding the logical ids falls back and still answers 200."""
    data = _cl(ctx, "ConfigFunction", "appconfigdata")
    app_id, env_id, profile_id = _APPCONFIG_LOGICAL_IDS
    refused = _error("StartConfigurationSession with logical ids",
                     lambda: data.start_configuration_session(
                         ApplicationIdentifier=app_id, EnvironmentIdentifier=env_id,
                         ConfigurationProfileIdentifier=profile_id))
    assert refused == ("ResourceNotFoundException", "Application not found"), refused

    def latest():
        token = data.start_configuration_session(
            ApplicationIdentifier=out["AppConfigApplicationId"],
            EnvironmentIdentifier=out["AppConfigEnvironmentId"],
            ConfigurationProfileIdentifier=out["AppConfigConfigurationProfileId"])[
            "InitialConfigurationToken"]
        return data.get_latest_configuration(ConfigurationToken=token)["Configuration"].read()

    content = _poll_until(ctx, latest, bool, timeout_s=180.0,
                          description="the deployed configuration to serve")
    assert json.loads(content) == {"useNewBackend": True}, f"AppConfig served {content!r}"

    result = _cl(ctx, "ConfigFunction", "lambda").invoke(
        FunctionName=out["LambdaFunctionName"], Payload=b"{}", LogType="Tail")
    assert "FunctionError" not in result, result.get("FunctionError")
    body = json.loads(result["Payload"].read())
    assert body == {"statusCode": 200, "body": '{"message": "Function executed"}'}, body
    tail = base64.b64decode(result["LogResult"]).decode()
    assert "Failed to retrieve AppConfig:" in tail, tail[-800:]
    assert "Falling back to default: useNewBackend = false" in tail, tail[-800:]

    ddb = _cl(ctx, "ConfigFunction", "dynamodb")
    item = {"contentId": {"S": ctx.unique_name("content-")},
            "marketplaceId_shoppableStrategy": {"S": "ATVPDKIKX0DER#default"}}
    ddb.put_item(TableName=out["AnnotationStagingTableName"], Item=item)
    got = ddb.get_item(TableName=out["AnnotationStagingTableName"], Key=item,
                       ConsistentRead=True).get("Item")
    assert got == item, f"GetItem returned {got!r}"


def _assume(ctx, role_arn: str) -> tuple[dict, str]:
    """Credentials for ``role_arn`` and the session's assumed-role ARN, past IAM propagation."""
    sts = ctx.client("sts")
    session = ctx.unique_name("s-")

    def attempt():
        try:
            return sts.assume_role(RoleArn=role_arn, RoleSessionName=session)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "AccessDenied":
                raise
            return None

    granted = _poll_until(ctx, attempt, bool, timeout_s=120.0,
                          description=f"role {role_arn} to be assumable")
    assert granted, f"role {role_arn!r} could not be assumed"
    c = granted["Credentials"]
    return ({"aws_access_key_id": c["AccessKeyId"], "aws_secret_access_key": c["SecretAccessKey"],
             "aws_session_token": c["SessionToken"]}, granted["AssumedRoleUser"]["Arn"])


def _read_as(ctx, creds, bucket: str, key: str):
    """``(body, None)`` for a read ``creds`` may make, else ``(None, (code, message))``."""
    try:
        s3 = ctx.client("s3", region=_HOME, creds=creds)
        return s3.get_object(Bucket=bucket, Key=key)["Body"].read(), None
    except ClientError as exc:
        return None, (exc.response["Error"]["Code"], exc.response["Error"].get("Message", ""))


def _assert_clickstream_reads_and_queue(ctx, state, out) -> None:
    """Once the stream consumers join the key policy, a consumer reads its object; a legacy role
    with an IAM grant is refused by KMS; a queued message reaches the consumer function."""
    kms = _cl(ctx, "ClickstreamData", "kms")
    policy = json.loads(kms.get_key_policy(KeyId=out["KmsKeyId"], PolicyName="default")["Policy"])
    policy["Statement"].append({
        "Sid": "QuartzDataPlaneAccess", "Effect": "Allow",
        "Principal": {"AWS": [out["WorkhorseRoleArn"], out["BasaltRoleArn"], out["OnyxRoleArn"]]},
        "Action": ["kms:Decrypt", "kms:GenerateDataKey"], "Resource": "*",
    })
    kms.put_key_policy(KeyId=out["KmsKeyId"], PolicyName="default", Policy=json.dumps(policy))
    bucket = out["ClickstreamBucketName"]

    basalt, _ = _assume(ctx, out["BasaltRoleArn"])
    body, err = _poll_until(ctx, lambda: _read_as(ctx, basalt, bucket, _BASALT_SAMPLE),
                            lambda r: r[1] is None or r[1][0] != "AccessDenied", timeout_s=180.0,
                            description="the consumer's read to be allowed")
    assert err is None, f"the basalt consumer's GetObject was refused: {err!r}"
    assert json.loads(body) == {"event": "sample"}, body

    legacy, session_arn = _assume(ctx, out["LegacyFlintRoleArn"])
    _, err = _poll_until(ctx, lambda: _read_as(ctx, legacy, bucket, _UNLISTED_OBJECT),
                         lambda r: r[1] is not None and "kms:Decrypt" in r[1][1],
                         timeout_s=180.0, description="the legacy read to reach KMS")
    assert err is not None and err[0] == "AccessDenied", f"the legacy GetObject returned {err!r}"
    assert f"User: {session_arn} is not authorized to perform: kms:Decrypt" in err[1], err

    lam = _cl(ctx, "ClickstreamData", "lambda")
    mappings = _poll_until(
        ctx, lambda: lam.list_event_source_mappings(
            FunctionName=out["CertifierLambdaName"])["EventSourceMappings"],
        lambda m: len(m) == 1 and m[0]["State"] == "Enabled", timeout_s=120.0,
        description="the queue mapping to be enabled")
    assert [m["State"] for m in mappings] == ["Enabled"], mappings
    log_group = lam.get_function_configuration(FunctionName=out["CertifierLambdaName"])[
        "LoggingConfig"]["LogGroup"]
    _cl(ctx, "ClickstreamData", "sqs").send_message(QueueUrl=out["StreamTrackerQueueUrl"],
                                                    MessageBody=ctx.unique_name("track-"))
    started = _poll_until(ctx, lambda: _log_lines(_cl(ctx, "ClickstreamData", "logs"), log_group,
                                                  "START RequestId"),
                          bool, timeout_s=300.0, description="the consumer function to run")
    assert started, f"no invocation of {out['CertifierLambdaName']!r} after the message was sent"


def _assert_ssm_documents(ctx, out) -> None:
    """The five command documents and the session document are active, parameters validated."""
    ssm = _cl(ctx, "SsmDocuments", "ssm")
    for command in ("clear-counters", "traffic-stop", "traffic-start", "set-role",
                    "set-hostname"):
        doc = ssm.describe_document(Name=f"{out['DocumentPrefix']}{command}")["Document"]
        assert (doc["Status"], doc["DocumentType"]) == ("Active", "Command"), doc
    content = json.loads(ssm.get_document(Name=f"{out['DocumentPrefix']}traffic-stop")[
        "Content"])
    assert content["parameters"]["args"]["allowedPattern"] == "^[^;\\\\<>*`&$!#]*$", content
    session = ssm.describe_document(
        Name=f"{out['DocumentPrefix'].removesuffix('BirchService-')}SessionManagerRunShell")[
        "Document"]
    assert (session["Status"], session["DocumentType"]) == ("Active", "Session"), session


def _assert_aurora(ctx, out) -> None:
    """The writer and reader are private with Performance Insights under the stack's key."""
    rds = _cl(ctx, "AuroraPostgres", "rds")
    cluster = _poll_until(
        ctx, lambda: rds.describe_db_clusters(DBClusterIdentifier=out["ClusterIdentifier"])[
            "DBClusters"][0],
        lambda c: c["Status"] == "available", timeout_s=900.0,
        description="the Aurora cluster to be available")
    assert (cluster["Status"], cluster["Engine"], cluster["EngineVersion"],
            cluster["Endpoint"]) == ("available", "aurora-postgresql", "17.4",
                                     out["ClusterEndpoint"]), cluster
    members = cluster["DBClusterMembers"]
    assert sorted(m["IsClusterWriter"] for m in members) == [False, True], members
    for member in members:
        instance = rds.describe_db_instances(
            DBInstanceIdentifier=member["DBInstanceIdentifier"])["DBInstances"][0]
        assert (instance["PubliclyAccessible"], instance["PerformanceInsightsEnabled"],
                instance["PerformanceInsightsKMSKeyId"],
                instance["PerformanceInsightsRetentionPeriod"],
                instance["MonitoringInterval"]) == (
            False, True, out["PerformanceInsightsKeyArn"], 731, 60), instance
    secret = json.loads(_cl(ctx, "AuroraPostgres", "secretsmanager").get_secret_value(
        SecretId=out["SecretArn"])["SecretString"])
    fields = {k: secret.get(k) for k in ("engine", "host", "port", "username")}
    assert fields == {"engine": "postgres", "host": out["ClusterEndpoint"], "port": 5432,
                      "username": "postgres"}, fields


def _assert_state_machine_failed(ctx, out, execution: str) -> None:
    """The execution fails with the function's error; a direct invoke raises the same."""
    sfn = _cl(ctx, "FailingStateMachine", "stepfunctions")
    described = _poll_until(ctx, lambda: sfn.describe_execution(executionArn=execution),
                            lambda d: d["status"] != "RUNNING", timeout_s=300.0,
                            description=f"execution {execution} to finish")
    assert (described["status"], described.get("error")) == ("FAILED", "RuntimeError"), described
    cause = json.loads(described["cause"])
    assert (cause["errorType"], cause["errorMessage"]) == ("RuntimeError", _VALIDATION_ERROR), cause
    result = _cl(ctx, "FailingStateMachine", "lambda").invoke(
        FunctionName=out["ProcessingLambdaName"], Payload=b"{}")
    error = json.loads(result["Payload"].read())
    assert (result.get("FunctionError"), error["errorType"], error["errorMessage"]) == (
        "Unhandled", "RuntimeError", _VALIDATION_ERROR), (result.get("FunctionError"), error)


def _start_crash_task(ctx, out) -> str:
    """Run one task of the crash-looping service's definition; its ARN."""
    response = _cl(ctx, "CrashLoopService", "ecs").run_task(
        cluster=out["ClusterName"], taskDefinition=out["TaskDefinitionArn"], launchType="FARGATE",
        networkConfiguration={"awsvpcConfiguration": {
            "subnets": out["TaskSubnetIds"].split(","),
            "securityGroups": [out["TaskSecurityGroupId"]], "assignPublicIp": "DISABLED"}})
    assert not response["failures"] and len(response["tasks"]) == 1, response["failures"]
    return response["tasks"][0]["taskArn"]


def _assert_crash_task_exited(ctx, out, task_arn: str) -> None:
    """The task stops with exit code 1, having logged the missing variable."""
    ecs = _cl(ctx, "CrashLoopService", "ecs")
    task = _poll_until(ctx, lambda: ecs.describe_tasks(cluster=out["ClusterName"],
                                                       tasks=[task_arn])["tasks"][0],
                       lambda t: t["lastStatus"] == "STOPPED", timeout_s=600.0,
                       description=f"task {task_arn} to stop")
    container = task["containers"][0]
    stop_code, stop_reason = task.get("stopCode"), task.get("stoppedReason")
    assert (stop_code, stop_reason) == _ESSENTIAL_EXIT, (
        f"the task stopped with {stop_code!r}: {stop_reason!r}")
    assert container.get("exitCode") == 1, container
    stream = f"service/service/{task_arn.rsplit('/', 1)[-1]}"
    logs = _cl(ctx, "CrashLoopService", "logs")

    def stdout_lines() -> list[str]:
        # The stream can appear a little after the task stops.
        try:
            return [e["message"] for e in logs.get_log_events(
                logGroupName=out["AppStdoutLogGroupName"], logStreamName=stream,
                startFromHead=True)["events"]]
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise
            return []

    lines = _poll_until(
        ctx, stdout_lines, lambda m: len(m) >= len(_MISSING_VARIABLE_LINES), timeout_s=120.0,
        description=f"the task's lines in {stream}")
    assert lines == _MISSING_VARIABLE_LINES, f"the task logged {lines!r}"


def _start_governed_job(ctx, out) -> str:
    """IAMAllowedPrincipals holds no grant on the table; start a run of the job; its id."""
    lf = ctx.client("lakeformation", region=_HOME)
    table = {"Table": {"DatabaseName": out["GlueDatabaseName"], "Name": out["GlueTableName"]}}
    grants = lf.list_permissions(
        Principal={"DataLakePrincipalIdentifier": "IAM_ALLOWED_PRINCIPALS"},
        Resource=table)["PrincipalResourcePermissions"]
    assert grants == [], f"IAMAllowedPrincipals holds {grants!r} on the table"
    return _cl(ctx, "LakeFormationEtl", "glue").start_job_run(JobName=out["GlueJobName"])[
        "JobRunId"]


def _assert_governed_job_refused(ctx, out, run_id: str) -> None:
    """The job run fails on the table's missing Lake Formation permission."""
    glue = _cl(ctx, "LakeFormationEtl", "glue")
    job_run = _poll_until(
        ctx, lambda: glue.get_job_run(JobName=out["GlueJobName"], RunId=run_id)["JobRun"],
        lambda r: r["JobRunState"] not in ("STARTING", "RUNNING", "STOPPING", "WAITING"),
        timeout_s=900.0, description=f"job run {run_id} to finish")
    assert job_run["JobRunState"] == "FAILED", job_run
    assert "Insufficient Lake Formation permission(s): Required Describe on usage_events" in (
        job_run.get("ErrorMessage", "")), job_run.get("ErrorMessage")


def _start_emr_step(ctx, out) -> str:
    """Add an HDFS listing step to the cluster once it is waiting; the step id."""
    emr = _cl(ctx, "SparkCluster", "emr")
    cluster = _poll_until(ctx, lambda: emr.describe_cluster(ClusterId=out["EmrClusterId"])[
        "Cluster"], lambda c: c["Status"]["State"] in ("WAITING", "TERMINATED",
                                                         "TERMINATED_WITH_ERRORS"),
                          timeout_s=900.0, description="the EMR cluster to wait for steps")
    assert cluster["Status"]["State"] == "WAITING", cluster["Status"]
    return emr.add_job_flow_steps(JobFlowId=out["EmrClusterId"], Steps=[{
        "Name": "list-hdfs-root", "ActionOnFailure": "CONTINUE",
        "HadoopJarStep": {"Jar": "command-runner.jar", "Args": ["hdfs", "dfs", "-ls", "/"]},
    }])["StepIds"][0]


def _assert_emr_step_and_configuration(ctx, out, step_id: str) -> None:
    """The cluster runs a step, its applications and Spark defaults as declared."""
    emr = _cl(ctx, "SparkCluster", "emr")
    step = _poll_until(ctx, lambda: emr.describe_step(ClusterId=out["EmrClusterId"],
                                                      StepId=step_id)["Step"],
                       lambda s: s["Status"]["State"] in ("COMPLETED", "FAILED", "CANCELLED"),
                       timeout_s=600.0, description=f"step {step_id} to finish")
    assert step["Status"]["State"] == "COMPLETED", step["Status"]
    cluster = emr.describe_cluster(ClusterId=out["EmrClusterId"])["Cluster"]
    assert sorted(a["Name"] for a in cluster["Applications"]) == [
        "Hadoop", "Pig", "Spark", "Zeppelin"], cluster["Applications"]
    defaults = {c["Classification"]: c.get("Properties", {}) for c in cluster["Configurations"]}
    assert (defaults["spark-defaults"]["spark.executor.instances"],
            defaults["spark-defaults"]["spark.driver.memory"]) == ("425", "60G"), defaults


def _assert_redshift_serves_and_health_alarm_period(ctx, out) -> None:
    """Both clusters are private and encrypted, one answers a query, and the inverted health
    alarm watches the global cluster's HealthStatus over the declared 300 s period."""
    redshift = _cl(ctx, "RedshiftClusters", "redshift")
    for key in ("AdhocClusterIdentifier", "GlobalClusterIdentifier"):
        cluster = _poll_until(
            ctx, lambda key=key: redshift.describe_clusters(ClusterIdentifier=out[key])[
                "Clusters"][0],
            lambda c: c["ClusterStatus"] == "available", timeout_s=600.0,
            description=f"cluster {out[key]} to be available")
        assert (cluster["ClusterStatus"], cluster["PubliclyAccessible"], cluster["Encrypted"],
                cluster["NodeType"]) == ("available", False, True, "ra3.xlplus"), cluster
    data = _cl(ctx, "RedshiftClusters", "redshift-data")
    statement = data.execute_statement(ClusterIdentifier=out["AdhocClusterIdentifier"],
                                       Database="quartzdb", SecretArn=out["AdminSecretArn"],
                                       Sql="SELECT 1 AS one")["Id"]
    described = _poll_until(ctx, lambda: data.describe_statement(Id=statement),
                            lambda d: d["Status"] in ("FINISHED", "FAILED", "ABORTED"),
                            timeout_s=300.0, description=f"statement {statement} to finish")
    assert described["Status"] == "FINISHED", described.get("Error")
    records = data.get_statement_result(Id=statement)["Records"]
    assert records == [[{"longValue": 1}]], records

    name = out["GlobalHealthAllAlarmName"]
    alarms = _cl(ctx, "RedshiftClusters", "cloudwatch").describe_alarms(AlarmNames=[name])[
        "MetricAlarms"]
    assert len(alarms) == 1, f"DescribeAlarms for {name} returned {len(alarms)} alarm(s)"
    alarm = alarms[0]
    watched = (alarm.get("Namespace"), alarm.get("MetricName"), alarm.get("Dimensions", []))
    want = ("AWS/Redshift", "HealthStatus",
            [{"Name": "ClusterIdentifier", "Value": out["GlobalClusterIdentifier"]}])
    assert watched == want, f"the health alarm watches {watched!r}, expected {want!r}"
    echoed = {key: alarm.get(key) for key in _HEALTH_ALARM_DECLARED}
    assert echoed == _HEALTH_ALARM_DECLARED, (
        f"the health alarm reports {echoed!r}, expected the declared {_HEALTH_ALARM_DECLARED!r}"
    )


#: The inverted cluster-health alarm as DescribeAlarms reports it: the Average of HealthStatus over
#: one 300 s period, alarming on one datapoint above 0.5, actions enabled, and its description.
_HEALTH_ALARM_DECLARED = {
    "Statistic": "Average",
    "Period": 300,
    "EvaluationPeriods": 1,
    "DatapointsToAlarm": 1,
    "Threshold": 0.5,
    "ComparisonOperator": "GreaterThanThreshold",
    "ActionsEnabled": True,
    "AlarmDescription": ("Alarm for quartz-global-basalt1 when cluster is unhealthy for "
                         "more than 5 minutes"),
}


def _record_retained(ctx, state) -> None:
    """Note each resource a template retains on delete, by its recorded physical id."""
    for part, name in state["stacks"].items():
        body = _cl(ctx, part, "cloudformation").get_template(
            StackName=name, TemplateStage="Original")["TemplateBody"]
        template = body if isinstance(body, dict) else json.loads(body)
        retained = {lid: r["Type"] for lid, r in template["Resources"].items()
                    if r.get("DeletionPolicy") == "Retain"
                    and r["Type"] == "AWS::Logs::LogGroup"}
        state["retained"] += [(part, rtype, pid) for rtype, pid, lid in
                              state["resources"].get(part, []) if lid in retained]


def _assert_retained_outlive_destroy(ctx, state) -> None:
    """The retained log groups and the kept data volume outlive the stacks."""
    assert state["retained"], "no template retains a log group; the app retains five"
    for part, _, group in state["retained"]:
        found = _cl(ctx, part, "logs").describe_log_groups(logGroupNamePrefix=group)["logGroups"]
        assert any(g["logGroupName"] == group for g in found), (
            f"log group {group!r} is retained on delete but is gone after `cdk destroy`"
        )
    ec2 = _cl(ctx, "PrivateNatServer", "ec2")
    for volume in state["kept_volumes"]:
        found = ec2.describe_volumes(VolumeIds=[volume])["Volumes"][0]
        assert found["State"] == "available", (
            f"volume {volume!r} is kept on termination; after destroy it is {found['State']!r}"
        )


def _assert_owned_resources_gone(ctx, outputs) -> None:
    """A sample of what the stacks owned, each answering not-found after destroy."""
    probes = [
        ("AliasFunctions", "alias function", "lambda", lambda c: c.get_function(
            FunctionName=outputs["AliasFunctions"]["SimpleEmailServiceLambdaName"]),
         ("ResourceNotFoundException",)),
        ("ClickstreamData", "clickstream bucket", "s3", lambda c: c.head_bucket(
            Bucket=outputs["ClickstreamData"]["ClickstreamBucketName"]), ("404",)),
        ("ClickstreamData", "tracker queue", "sqs", lambda c: c.get_queue_attributes(
            QueueUrl=outputs["ClickstreamData"]["StreamTrackerQueueUrl"]),
         ("AWS.SimpleQueueService.NonExistentQueue", "QueueDoesNotExist")),
        ("RedshiftClusters", "adhoc cluster", "redshift", lambda c: c.describe_clusters(
            ClusterIdentifier=outputs["RedshiftClusters"]["AdhocClusterIdentifier"]),
         ("ClusterNotFound",)),
        ("AuroraPostgres", "Aurora cluster", "rds", lambda c: c.describe_db_clusters(
            DBClusterIdentifier=outputs["AuroraPostgres"]["ClusterIdentifier"]),
         ("DBClusterNotFoundFault",)),
        ("CacheTransit", "cache cluster", "elasticache", lambda c: c.describe_cache_clusters(
            CacheClusterId=outputs["CacheTransit"]["ElastiCacheClusterId"]),
         ("CacheClusterNotFound",)),
        ("TransitFirewall", "outbound firewall", "network-firewall", lambda c: c.describe_firewall(
            FirewallArn=outputs["TransitFirewall"]["OutboundFirewallArn"]),
         ("ResourceNotFoundException",)),
        ("ConfigFunction", "annotation table", "dynamodb", lambda c: c.describe_table(
            TableName=outputs["ConfigFunction"]["AnnotationStagingTableName"]),
         ("ResourceNotFoundException",)),
        ("FailingStateMachine", "state machine", "stepfunctions",
         lambda c: c.describe_state_machine(
             stateMachineArn=outputs["FailingStateMachine"]["StateMachineArn"]),
         ("StateMachineDoesNotExist",)),
        ("LakeFormationEtl", "governed job", "glue", lambda c: c.get_job(
            JobName=outputs["LakeFormationEtl"]["GlueJobName"]), ("EntityNotFoundException",)),
        ("GpuInference", "inference repository", "ecr", lambda c: c.describe_repositories(
            repositoryNames=[outputs["GpuInference"]["EcrRepositoryName"]]),
         ("RepositoryNotFoundException",)),
    ]
    for part, label, service, probe, codes in probes:
        code, _ = _error(f"{label} probe", lambda probe=probe, part=part, service=service:
                         probe(_cl(ctx, part, service)))
        assert code in codes, f"after destroy, the {label} answered {code!r}, expected {codes!r}"
    emr = _cl(ctx, "SparkCluster", "emr").describe_cluster(
        ClusterId=outputs["SparkCluster"]["EmrClusterId"])["Cluster"]["Status"]["State"]
    assert emr == "TERMINATED", f"after destroy, the EMR cluster is {emr!r}"
    try:
        tgw = [t["State"] for t in _cl(ctx, "CacheTransit", "ec2").describe_transit_gateways(
            TransitGatewayIds=[outputs["CacheTransit"]["TransitGatewayId"]])["TransitGateways"]]
    except ClientError as exc:
        # EC2 lists a deleted transit gateway for a while, then forgets it.
        if exc.response["Error"]["Code"] != "InvalidTransitGatewayID.NotFound":
            raise
        tgw = []
    assert tgw in ([], ["deleted"]), f"after destroy, the transit gateway is {tgw!r}"


def _principal_arn(ctx, caller_arn: str) -> str:
    """The IAM ARN of the caller: an assumed role's role, with its path; any other ARN as is."""
    if ":assumed-role/" not in caller_arn:
        return caller_arn
    role = caller_arn.split(":assumed-role/", 1)[1].split("/", 1)[0]
    return ctx.client("iam").get_role(RoleName=role)["Role"]["Arn"]


def _s3_prefix_list(ctx, region: str) -> str:
    """The id of the AWS-managed S3 prefix list in ``region``."""
    lists = ctx.client("ec2", region=region).describe_managed_prefix_lists(Filters=[{
        "Name": "prefix-list-name", "Values": [f"com.amazonaws.{region}.s3"]}])["PrefixLists"]
    assert len(lists) == 1, f"{region} has S3 prefix lists {lists!r}"
    return lists[0]["PrefixListId"]


def _zones(ec2) -> list[str]:
    """Standard availability zones, sorted: no local or wavelength zones, none needing opt-in."""
    zones = ec2.describe_availability_zones()["AvailabilityZones"]
    return sorted(
        z["ZoneName"]
        for z in zones
        if z.get("State", "available") == "available"
        and z.get("ZoneType", "availability-zone") == "availability-zone"
        and z.get("OptInStatus", "opt-in-not-required") == "opt-in-not-required"
    )


def _physical_ids(state, part: str, resource_type: str) -> list[str]:
    """The recorded physical ids of ``resource_type`` in the stack ``part``."""
    return [pid for rtype, pid, _ in state["resources"].get(part, []) if rtype == resource_type]


def _record_resources(ctx, state) -> None:
    """Record every stack's (type, physical id, logical id), merged so a deleted stack keeps it.

    A stack is read by its id once known, which still lists a deleted stack's resources.
    """
    ids = state.setdefault("stack_ids", {})
    for part, name in state["stacks"].items():
        cfn = _cl(ctx, part, "cloudformation")
        try:
            if part not in ids:
                ids[part] = cfn.describe_stacks(StackName=name)["Stacks"][0]["StackId"]
            found = [
                (r["ResourceType"], r["PhysicalResourceId"], r["LogicalResourceId"])
                for page in cfn.get_paginator("list_stack_resources").paginate(
                    StackName=ids[part])
                for r in page["StackResourceSummaries"]
                if r.get("PhysicalResourceId")
            ]
        except ClientError as exc:
            if _stack_missing(exc):
                continue
            raise
        known = state["resources"].setdefault(part, [])
        known.extend(row for row in found if row not in known)


def _record_kept_volumes(ctx, state) -> None:
    """Note the app server's volumes that outlive it, while the instance still lists them."""
    ec2 = _cl(ctx, "PrivateNatServer", "ec2")
    for instance_id in _physical_ids(state, "PrivateNatServer", "AWS::EC2::Instance"):
        try:
            reservations = ec2.describe_instances(InstanceIds=[instance_id])["Reservations"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "InvalidInstanceID.NotFound":
                raise
            continue
        for instance in (i for r in reservations for i in r["Instances"]):
            for mapping in instance.get("BlockDeviceMappings", []):
                volume = mapping["Ebs"]["VolumeId"]
                if not mapping["Ebs"]["DeleteOnTermination"] and volume not in state[
                        "kept_volumes"]:
                    state["kept_volumes"].append(volume)


def _log_lines(logs, log_group: str, needle: str) -> list[str]:
    """Every message in ``log_group`` that contains ``needle``; an absent group has none yet."""
    try:
        return [
            e["message"]
            for page in logs.get_paginator("filter_log_events").paginate(
                logGroupName=log_group, filterPattern=f'"{needle}"')
            for e in page["events"]
        ]
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "ResourceNotFoundException":
            return []
        raise


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _raise_if_budget_spent(ctx, what: str) -> None:
    """A wait the run budget ended is not graded."""
    if _budget_spent(ctx):
        raise TimeoutError(f"the run budget ended while waiting for {what}; not graded")


def _poll_until(ctx, probe, predicate, *, timeout_s: float, description: str):
    """Poll probe() every 2 s until predicate(result) holds; return the final result."""
    deadline = time.monotonic() + _budget_s(ctx, timeout_s)
    last = probe()
    while not predicate(last) and time.monotonic() < deadline:
        time.sleep(_POLL_S)
        last = probe()
    if not predicate(last):
        _raise_if_budget_spent(ctx, description)
    return last


def _error(label: str, fn) -> tuple[str, str]:
    """The AWS ``(code, message)`` a call raises; raises naming ``label`` if the call succeeds."""
    try:
        fn()
    except ClientError as exc:
        return str(exc.response["Error"]["Code"]), str(exc.response["Error"].get("Message", ""))
    raise AssertionError(f"the {label} call succeeded but was expected to be refused")


def _stack_missing(exc: ClientError) -> bool:
    """True only for CloudFormation's own not-found refusal for a stack name."""
    error = exc.response["Error"]
    return error["Code"] == "ValidationError" and "does not exist" in str(error.get("Message", ""))


def _stage_app(ctx, name: str) -> Path:
    """Copy ``deployments/<name>`` into a temp dir so ``cdk.out`` never lands in the repo."""
    source = Path(__file__).parent / "deployments" / name
    assert source.is_dir(), (
        f"the CDK app this check references is missing from disk: {source} does not exist "
        f"(artifact defect, not a missing prerequisite)"
    )
    assert (source / "app.py").is_file() and (source / "cdk.json").is_file(), (
        f"the CDK app at {source} is incomplete: app.py present={(source / 'app.py').is_file()}, "
        f"cdk.json present={(source / 'cdk.json').is_file()}"
    )
    work = Path(tempfile.mkdtemp(prefix=f"sim2real-{name}-"))
    ctx.on_cleanup(lambda: shutil.rmtree(work, ignore_errors=True))
    staged = work / name
    shutil.copytree(source, staged, ignore=shutil.ignore_patterns(
        "cdk.out", "out-*", ".venv", "__pycache__", "node_modules"))
    return staged


def _bootstrap(ctx, state) -> None:
    """``cdk bootstrap`` every region for one per-run qualifier, in a scratch cwd of its own."""
    ctx.verify_account_safety()
    scratch = Path(tempfile.mkdtemp(prefix="sim2real-tm-boot-"))
    ctx.on_cleanup(lambda: shutil.rmtree(scratch, ignore_errors=True))
    command = [
        "cdk", "bootstrap", *[f"aws://{state['account']}/{r}" for r in _REGIONS],
        "--qualifier", state["qualifier"],
        "--toolkit-stack-name", state["toolkit"],
        "--bootstrap-kms-key-id", "AWS_MANAGED_KEY",
        # The staging bucket's name does not carry the sim2real prefix, so tag it via the stack.
        "--tags", f"sim2real={CHECK}",
        *_CDK_FLAGS,
    ]
    _run_cli(ctx, command, scratch, _BOOTSTRAP_TIMEOUT_S,
             f"`cdk bootstrap` for qualifier {state['qualifier']!r}")


def _cdk(ctx, work: Path, args: list[str], context: dict[str, str], *,
         timeout_s: float) -> None:
    """Run the CDK CLI in *work* with the app's context; asserts it exits 0."""
    ctx.verify_account_safety()
    cmd = ["cdk", *args, *_CDK_FLAGS, "--no-color"]
    for key, value in context.items():
        cmd += ["--context", f"{key}={value}"]
    _run_cli(ctx, cmd, work, timeout_s, f"`cdk {' '.join(args[:2])}`")


def _run_cli(ctx, cmd: list[str], cwd: Path, timeout_s: float, what: str) -> None:
    """Run ``cmd`` in ``cwd`` under the run budget; asserts it exits 0, quoting the output tail."""
    try:
        result = subprocess.run(cmd, cwd=cwd, env=ctx.subprocess_env(), capture_output=True,
                                text=True, timeout=_budget_s(ctx, timeout_s))
    except subprocess.TimeoutExpired:
        _raise_if_budget_spent(ctx, what)
        raise
    assert result.returncode == 0, (
        f"{what} exited {result.returncode}, expected 0; output tail: "
        f"{(result.stdout + result.stderr)[-1500:]!r}"
    )


def _delete_stacks_and_wait(ctx, parts: list[str], names: dict[str, str], timeout_s: float,
                            before_retry=None, retain: tuple[str, ...] = ()) -> None:
    """Delete the stacks of *parts* at once, each in its region, and poll all of them to gone.

    A stack that reaches DELETE_FAILED is deleted once more, after ``before_retry(part)``, once
    the others settle, keeping the *retain* logical ids; raises naming every stack still not
    gone with the reasons its resources failed to delete.
    """
    deadline = time.monotonic() + timeout_s
    failed = _delete_and_settle(ctx, parts, names, timeout_s)
    if failed and before_retry is not None:
        for part in failed:
            before_retry(part)
    if failed:
        # The retry shares the one budget, so the whole delete never outlasts timeout_s.
        failed = _delete_and_settle(ctx, failed, names,
                                    max(1.0, deadline - time.monotonic()), retain)
    if failed:
        reasons = {names[p]: _delete_failures(ctx, p, names[p]) for p in failed}
        raise AssertionError(f"stacks were not deleted: {reasons!r}")


def _delete_failures(ctx, part: str, stack: str) -> list[str]:
    """Each resource's latest DELETE_FAILED reason in *stack*, and each one still deleting."""
    try:
        events = _cl(ctx, part, "cloudformation").describe_stack_events(
            StackName=stack)["StackEvents"]
    except ClientError as exc:
        return [f"events unreadable: {exc.response['Error'].get('Message', '')}"]
    seen: dict[str, str] = {}
    for event in events:
        if event["ResourceStatus"] == "DELETE_FAILED" and event["LogicalResourceId"] != stack:
            seen.setdefault(event["LogicalResourceId"], event.get("ResourceStatusReason", ""))
    try:
        resources = _cl(ctx, part, "cloudformation").describe_stack_resources(
            StackName=stack)["StackResources"]
    except ClientError:
        resources = []
    seen.update({r["LogicalResourceId"]: f"still {r['ResourceStatus']} ({r['ResourceType']})"
                 for r in resources if r["ResourceStatus"] == "DELETE_IN_PROGRESS"})
    return [f"{lid}: {reason}" for lid, reason in seen.items()]


def _delete_and_settle(ctx, parts: list[str], names: dict[str, str],
                       timeout_s: float, retain: tuple[str, ...] = ()) -> list[str]:
    """Delete *parts*, keeping *retain*; wait for each to go or fail; those not gone."""
    pending = []
    for part in parts:
        kept = {"RetainResources": list(retain)} if retain else {}
        try:
            _cl(ctx, part, "cloudformation").delete_stack(StackName=names[part], **kept)
            pending.append(part)
        except ClientError as exc:
            if "delete stack operation is already in progress" in str(exc):
                pending.append(part)
            elif not _stack_missing(exc):
                raise
    failed: list[str] = []
    deadline = time.monotonic() + timeout_s
    while pending and time.monotonic() <= deadline:
        for part in list(pending):
            try:
                status = _cl(ctx, part, "cloudformation").describe_stacks(
                    StackName=names[part])["Stacks"][0]["StackStatus"]
            except ClientError as exc:
                if not _stack_missing(exc):
                    raise
                status = "DELETE_COMPLETE"
            if status in ("DELETE_COMPLETE", "DELETE_FAILED"):
                pending.remove(part)
                if status == "DELETE_FAILED":
                    failed.append(part)
        if pending:
            time.sleep(_POLL_S)
    return failed + pending


def _empty_and_delete_bucket(ctx, bucket: str, region: str, *, delete: bool = True) -> None:
    """Purge every version and delete marker, then (unless told not to) the bucket."""
    s3 = ctx.client("s3", region=region)
    try:
        for page in s3.get_paginator("list_object_versions").paginate(Bucket=bucket):
            objects = [
                {"Key": o["Key"], "VersionId": o["VersionId"]}
                for o in page.get("Versions", []) + page.get("DeleteMarkers", [])
            ]
            if objects:
                s3.delete_objects(Bucket=bucket, Delete={"Objects": objects})
        if delete:
            s3.delete_bucket(Bucket=bucket)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchBucket", "404"):
            raise


def _reap_log_group(logs, name: str, *, reads: int = 3, budget_s: float = 180.0) -> None:
    """Delete log group ``name`` until ``reads`` consecutive reads find it absent."""
    deadline = time.monotonic() + budget_s
    absent = 0
    while absent < reads:
        groups = logs.describe_log_groups(logGroupNamePrefix=name)["logGroups"]
        if any(g["logGroupName"] == name for g in groups):
            absent = 0
            try:
                logs.delete_log_group(logGroupName=name)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                    raise
        else:
            absent += 1
        if absent < reads:
            if time.monotonic() > deadline:
                raise AssertionError(f"log group {name!r} still present after {budget_s}s")
            time.sleep(_POLL_S)


def _delete_secret(ctx, arn: str, region: str) -> None:
    """Delete a secret the stack left scheduled for deletion, without a recovery window."""
    try:
        ctx.client("secretsmanager", region=region).delete_secret(
            SecretId=arn, ForceDeleteWithoutRecovery=True)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _delete_volume(ctx, volume: str, region: str) -> None:
    """Delete a data volume kept past its instance; one already gone is fine."""
    try:
        ctx.client("ec2", region=region).delete_volume(VolumeId=volume)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "InvalidVolume.NotFound":
            raise


def _delete_task_definition(ctx, arn: str, region: str) -> None:
    """Delete one deregistered task definition revision; raises on any reported failure."""
    failures = ctx.client("ecs", region=region).delete_task_definitions(
        taskDefinitions=[arn]).get("failures", [])
    if failures:
        raise AssertionError(f"DeleteTaskDefinitions refused {arn}: {failures!r}")


def _restore_lake_settings(ctx, state) -> None:
    """Put the account's data lake settings back exactly as they were before the run."""
    lf = ctx.client("lakeformation", region=_HOME)
    prior = state["prior_lake_settings"]
    lf.put_data_lake_settings(DataLakeSettings=prior)
    current = lf.get_data_lake_settings()["DataLakeSettings"]
    assert current.get("DataLakeAdmins", []) == prior.get("DataLakeAdmins", []), (
        f"the data lake admins are {current.get('DataLakeAdmins')!r} after restoring "
        f"{prior.get('DataLakeAdmins')!r}"
    )


def _bootstrap_remnants(ctx, state) -> list[str]:
    """What bootstrap left behind, by exact name. Never a prefix sweep across the account."""
    qualifier, account = state["qualifier"], state["account"]
    remaining: list[str] = []
    for region in _REGIONS:
        try:
            status = ctx.client("cloudformation", region=region).describe_stacks(
                StackName=state["toolkit"])["Stacks"][0]["StackStatus"]
            if status != "DELETE_COMPLETE":
                remaining.append(f"toolkit stack {state['toolkit']} in {region} in {status}")
        except ClientError as exc:
            if not _stack_missing(exc):
                raise
        staging = f"cdk-{qualifier}-assets-{account}-{region}"
        try:
            ctx.client("s3", region=region).head_bucket(Bucket=staging)
            remaining.append(f"staging bucket {staging}")
        except ClientError as exc:
            if exc.response["Error"]["Code"] not in ("NoSuchBucket", "404"):
                raise
        try:
            ctx.client("ssm", region=region).get_parameter(
                Name=f"/cdk-bootstrap/{qualifier}/version")
            remaining.append(f"bootstrap version parameter in {region}")
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ParameterNotFound":
                raise
        repository = f"cdk-{qualifier}-container-assets-{account}-{region}"
        try:
            ctx.client("ecr", region=region).describe_repositories(repositoryNames=[repository])
            remaining.append(f"container assets repository {repository}")
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "RepositoryNotFoundException":
                raise
    iam = ctx.client("iam")
    roles = [role["RoleName"] for page in iam.get_paginator("list_roles").paginate()
             for role in page["Roles"] if role["RoleName"].startswith(f"cdk-{qualifier}-")]
    if roles:
        remaining.append(f"bootstrap roles {roles!r}")
    return remaining


def _teardown(ctx, state) -> None:
    """Run every teardown step, collecting each failure; raise naming all of them."""
    errors: list[str] = []
    for label, fn in _teardown_steps(ctx, state, errors):
        try:
            fn()
        except Exception as exc:  # noqa: BLE001 — collected and raised below, never swallowed
            errors.append(f"{label}: {exc!r}")
    if errors:
        raise AssertionError("teardown left residue: " + "; ".join(errors))


def _teardown_steps(ctx, state, errors: list[str]):
    """Yield ``(label, step)`` in order: the app stacks, what they retain or leave behind, the
    account's data lake settings, then bootstrap itself; ``errors`` holds the failed steps."""
    end = time.monotonic() + _TEARDOWN_S

    def left(reserve: float = 0.0) -> float:
        return max(1.0, end - reserve - time.monotonic())

    stacks = state["stacks"]
    yield "stack resource inventory", lambda: _record_resources(ctx, state)
    yield "kept volume inventory", lambda: _record_kept_volumes(ctx, state)

    def empty_buckets(part: str) -> None:
        # A bucket refilled after its auto-delete handler ran fails the stack's delete.
        for bucket in _physical_ids(state, part, "AWS::S3::Bucket"):
            _empty_and_delete_bucket(ctx, bucket, _PARTS[part], delete=False)

    # The governed job's stack needs the data lake settings until it is gone.
    first = [part for part in stacks if part != "LakeFormationSettings"]
    failed_before = len(errors)
    yield "app stacks", lambda: _delete_stacks_and_wait(
        ctx, first, stacks, left(_AFTER_STACKS_S), empty_buckets)
    # The settings outlive a failed delete only until the next step puts the prior ones back.
    yield "data lake settings stack", lambda: _delete_stacks_and_wait(
        ctx, ["LakeFormationSettings"], stacks, left(_AFTER_STACKS_S),
        retain=("DataLakeSettings",))
    apps_gone = len(errors) == failed_before
    yield "data lake settings", lambda: _restore_lake_settings(ctx, state)
    # A stack a timed-out deploy kept creating may hold resources the first inventory missed.
    yield "stack resource inventory after delete", lambda: _record_resources(ctx, state)
    for part in stacks:
        region = _PARTS[part]
        for arn in _physical_ids(state, part, "AWS::SecretsManager::Secret"):
            yield f"secret {arn}", lambda arn=arn, region=region: _delete_secret(ctx, arn, region)
        for arn in _physical_ids(state, part, "AWS::ECS::TaskDefinition"):
            # Deleting a stack only deregisters a task definition; INACTIVE revisions stay listed.
            yield (f"task definition {arn}",
                   lambda arn=arn, region=region: _delete_task_definition(ctx, arn, region))
    for volume in state["kept_volumes"]:
        yield (f"kept volume {volume}",
               lambda volume=volume: _delete_volume(ctx, volume, _PARTS["PrivateNatServer"]))
    log_groups = [(part, f"/aws/lambda/{fn}") for part in stacks
                  for fn in _physical_ids(state, part, "AWS::Lambda::Function")]
    log_groups += [(part, group) for part in stacks
                   for group in _physical_ids(state, part, "AWS::Logs::LogGroup")]
    log_groups += [(part, f"/aws/ecs/containerinsights/{cluster}/performance")
                   for part in ("FargateWebApp", "FirelensService")
                   for cluster in _physical_ids(state, part, "AWS::ECS::Cluster")]
    log_groups += [("AuroraPostgres", f"/aws/rds/cluster/{cluster}/postgresql")
                   for cluster in _physical_ids(state, "AuroraPostgres", "AWS::RDS::DBCluster")]
    for part, name in log_groups:
        logs = _cl(ctx, part, "logs")
        # Never below the time its three absent reads take, so a gone group is not residue.
        yield f"log group {name}", lambda logs=logs, name=name: _reap_log_group(
            logs, name, budget_s=max(10.0, min(180.0, left(120.0))))

    if apps_gone:
        for region in _REGIONS:
            staging = f"cdk-{state['qualifier']}-assets-{state['account']}-{region}"
            yield (f"staging bucket {staging}",
                   lambda staging=staging, region=region: _empty_and_delete_bucket(
                       ctx, staging, region))
        toolkits = {f"toolkit@{region}": state["toolkit"] for region in _REGIONS}
        yield f"toolkit stack {state['toolkit']}", lambda: _delete_toolkits(ctx, toolkits,
                                                                            left())
        yield "bootstrap remnants", lambda: _assert_no_bootstrap_remnants(ctx, state)
    else:
        # A leftover app stack still needs the toolkit's cfn-exec role to be deleted later.
        yield "toolkit stacks", lambda: _kept_toolkit(state)


def _kept_toolkit(state) -> None:
    """The toolkit outlives a stack that was not deleted, which still needs its exec role."""
    raise AssertionError(f"staging buckets and toolkit stack {state['toolkit']} kept: an app "
                         f"stack was not deleted")


def _assert_no_bootstrap_remnants(ctx, state) -> None:
    """Nothing bootstrap created is left in any region."""
    remaining = _bootstrap_remnants(ctx, state)
    assert not remaining, f"bootstrap remnants still present: {remaining!r}"


def _delete_toolkits(ctx, toolkits: dict[str, str], budget_s: float) -> None:
    """Delete the toolkit stack in every region at once and wait for each to go."""
    pending = {}
    for key, name in toolkits.items():
        region = key.split("@", 1)[1]
        cfn = ctx.client("cloudformation", region=region)
        try:
            cfn.delete_stack(StackName=name)
            pending[region] = cfn
        except ClientError as exc:
            if not _stack_missing(exc):
                raise
    deadline = time.monotonic() + min(900.0, budget_s)
    failed = []
    while pending and time.monotonic() <= deadline:
        for region, cfn in list(pending.items()):
            try:
                status = cfn.describe_stacks(StackName=toolkits[f"toolkit@{region}"])[
                    "Stacks"][0]["StackStatus"]
            except ClientError as exc:
                if not _stack_missing(exc):
                    raise
                status = "DELETE_COMPLETE"
            if status in ("DELETE_COMPLETE", "DELETE_FAILED"):
                del pending[region]
                if status == "DELETE_FAILED":
                    failed.append(region)
        if pending:
            time.sleep(_POLL_S)
    if failed or pending:
        raise AssertionError(f"toolkit stacks not deleted in {sorted(failed + list(pending))!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
