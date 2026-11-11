"""emr-hive-query-reads-glue-catalog-table-positive."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "emr-hive-query-reads-glue-catalog-table-positive"
GROUP = "resource-binding"
SERVICES = ["emr", "glue", "s3"]

_GLUE_HIVE_SITE = {
    "Classification": "hive-site",
    "Properties": {
        "hive.metastore.client.factory.class": "com.amazonaws.glue.catalog.metastore.AWSGlueDataCatalogHiveClientFactory",
        "hive.metastore.schema.verification": "false",
    },
}


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:e2e", "dp:api", "plane:data")
def run(ctx) -> None:
    """A Hive query on an EMR cluster reads real row data through a Glue Data Catalog table
    definition whose StorageDescriptor.Location points at S3."""
    bucket = _create_bucket(ctx)
    # Roles before the network: cleanup runs LIFO, so the network teardown, which waits for the
    # cluster to terminate, finishes before the roles EMR needs to terminate it are deleted.
    roles = _create_emr_roles(ctx)
    subnet_id = _pick_default_subnet(ctx)

    db = _hive_safe_name(ctx, "sim2real_db_")
    table = "sample_tbl"
    _create_glue_database(ctx, db)
    _put_text(ctx, bucket, "data/sample.csv", "1,alpha\n2,beta\n3,gamma\n")
    _create_glue_csv_table(
        ctx,
        db,
        table,
        f"s3://{bucket}/data/",
        [{"Name": "id", "Type": "string"}, {"Name": "name", "Type": "string"}],
    )

    cluster_id = _launch_cluster_with_retry(ctx, roles, subnet_id, [_GLUE_HIVE_SITE], bucket)
    _wait_for_cluster_ready(ctx, cluster_id)

    script = (
        f'hive -S -e "SELECT count(*) FROM {db}.{table};" > /tmp/out.txt 2>&1\n'
        "rc=$?\n"
        f"aws s3 cp /tmp/out.txt s3://{bucket}/results/count.txt\n"
        "exit $rc\n"
    )
    _, state = _run_shell_step(ctx, cluster_id, "hive-count-glue-table", script)
    assert state == "COMPLETED", f"hive query against Glue-catalog-backed table failed: {state}"
    text = _get_text(ctx, bucket, "results/count.txt").strip()
    last_line = text.splitlines()[-1].strip() if text else ""
    assert last_line == "3", f"unexpected row count read through the Glue Catalog table: {text!r}"


# ===== helpers =====

_ROLE_TRUST_EC2 = {
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"}, "Action": "sts:AssumeRole"}],
}
_ROLE_TRUST_EMR = {
    "Version": "2012-10-17",
    "Statement": [
        {"Effect": "Allow", "Principal": {"Service": "elasticmapreduce.amazonaws.com"}, "Action": "sts:AssumeRole"}
    ],
}


def _hive_safe_name(ctx, prefix: str) -> str:
    return ctx.unique_name(prefix).replace("-", "_")


def _create_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-emrglue-")
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=name)
    else:
        s3.create_bucket(Bucket=name, CreateBucketConfiguration={"LocationConstraint": ctx.region})

    def _cleanup():
        objs = s3.list_objects_v2(Bucket=name).get("Contents", [])
        if objs:
            failed = s3.delete_objects(Bucket=name, Delete={"Objects": [{"Key": o["Key"]} for o in objs]}).get("Errors")
            if failed:
                raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
        s3.delete_bucket(Bucket=name)

    ctx.on_cleanup(_cleanup)
    return name


def _put_text(ctx, bucket: str, key: str, text: str) -> None:
    ctx.client("s3").put_object(Bucket=bucket, Key=key, Body=text.encode("utf-8"))


def _get_text(ctx, bucket: str, key: str) -> str:
    body = ctx.client("s3").get_object(Bucket=bucket, Key=key)["Body"].read()
    return body.decode("utf-8", errors="replace")


def _pick_default_subnet(ctx) -> str:
    """This check's private subnet (see _private_network)."""
    return _private_network(ctx)[1]


def _create_glue_database(ctx, name: str) -> None:
    glue = ctx.client("glue")
    glue.create_database(DatabaseInput={"Name": name})
    ctx.on_cleanup(lambda: glue.delete_database(Name=name))


def _create_glue_csv_table(ctx, db: str, table: str, location: str, columns: list) -> None:
    glue = ctx.client("glue")
    glue.create_table(
        DatabaseName=db,
        TableInput={
            "Name": table,
            "TableType": "EXTERNAL_TABLE",
            "Parameters": {"classification": "csv", "EXTERNAL": "TRUE"},
            "StorageDescriptor": {
                "Columns": columns,
                "Location": location,
                "InputFormat": "org.apache.hadoop.mapred.TextInputFormat",
                "OutputFormat": "org.apache.hadoop.hive.ql.io.HiveIgnoreKeyTextOutputFormat",
                "SerdeInfo": {
                    "SerializationLibrary": "org.apache.hadoop.hive.serde2.lazy.LazySimpleSerDe",
                    "Parameters": {"field.delim": ","},
                },
            },
        },
    )
    ctx.on_cleanup(lambda: glue.delete_table(DatabaseName=db, Name=table))


def _create_emr_roles(ctx, deny_glue: bool = False) -> dict[str, str]:
    import json

    iam = ctx.client("iam")
    svc_role_name = ctx.unique_name("sim2real-emr-svc-")
    ec2_role_name = ctx.unique_name("sim2real-emr-ec2-")
    profile_name = ec2_role_name

    iam.create_role(RoleName=svc_role_name, AssumeRolePolicyDocument=json.dumps(_ROLE_TRUST_EMR))
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=svc_role_name))
    iam.attach_role_policy(
        RoleName=svc_role_name, PolicyArn="arn:aws:iam::aws:policy/service-role/AmazonElasticMapReduceRole"
    )
    ctx.on_cleanup(
        lambda: iam.detach_role_policy(
            RoleName=svc_role_name, PolicyArn="arn:aws:iam::aws:policy/service-role/AmazonElasticMapReduceRole"
        )
    )

    iam.create_role(RoleName=ec2_role_name, AssumeRolePolicyDocument=json.dumps(_ROLE_TRUST_EC2))
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=ec2_role_name))
    iam.attach_role_policy(
        RoleName=ec2_role_name, PolicyArn="arn:aws:iam::aws:policy/service-role/AmazonElasticMapReduceforEC2Role"
    )
    ctx.on_cleanup(
        lambda: iam.detach_role_policy(
            RoleName=ec2_role_name, PolicyArn="arn:aws:iam::aws:policy/service-role/AmazonElasticMapReduceforEC2Role"
        )
    )

    if deny_glue:
        deny_doc = {"Version": "2012-10-17", "Statement": [{"Effect": "Deny", "Action": "glue:*", "Resource": "*"}]}
        iam.put_role_policy(RoleName=ec2_role_name, PolicyName="DenyGlueCatalog", PolicyDocument=json.dumps(deny_doc))

        def _cleanup_deny():
            try:
                iam.delete_role_policy(RoleName=ec2_role_name, PolicyName="DenyGlueCatalog")
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "NoSuchEntity":
                    raise

        ctx.on_cleanup(_cleanup_deny)

    iam.create_instance_profile(InstanceProfileName=profile_name)
    ctx.on_cleanup(lambda: iam.delete_instance_profile(InstanceProfileName=profile_name))
    iam.add_role_to_instance_profile(InstanceProfileName=profile_name, RoleName=ec2_role_name)
    ctx.on_cleanup(
        lambda: iam.remove_role_from_instance_profile(InstanceProfileName=profile_name, RoleName=ec2_role_name)
    )

    _wait_for_instance_profile_ready(ctx, profile_name)
    return {"service_role": svc_role_name, "ec2_role": ec2_role_name, "instance_profile": profile_name}


def _wait_for_instance_profile_ready(ctx, profile_name: str, timeout_s: float = 60.0) -> None:
    iam = ctx.client("iam")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            iam.get_instance_profile(InstanceProfileName=profile_name)
            time.sleep(2)  # extra buffer for IAM->EMR/EC2 cross-service propagation
            return
        except iam.exceptions.NoSuchEntityException:
            time.sleep(2)
    raise AssertionError(f"instance profile {profile_name} never became visible")


def _launch_cluster(ctx, roles: dict[str, str], subnet_id: str, configurations: list, bucket: str) -> str:
    emr = ctx.client("emr")
    name = ctx.unique_name("sim2real-emrglue-cluster-")
    resp = emr.run_job_flow(
        Name=name,
        ReleaseLabel="emr-6.15.0",
        Applications=[{"Name": "Hadoop"}, {"Name": "Hive"}, {"Name": "Spark"}],
        Configurations=configurations,
        Instances={
            "InstanceGroups": [
                {"InstanceRole": "MASTER", "InstanceType": "m5.xlarge", "InstanceCount": 1},
                {"InstanceRole": "CORE", "InstanceType": "m5.xlarge", "InstanceCount": 1},
            ],
            "Ec2SubnetId": subnet_id,
            "KeepJobFlowAliveWhenNoSteps": True,
            "TerminationProtected": False,
        },
        ServiceRole=roles["service_role"],
        JobFlowRole=roles["instance_profile"],
        VisibleToAllUsers=True,
        LogUri=f"s3://{bucket}/emr-logs/",
        Tags=[{"Key": "sim2real", "Value": "emr-glue-s3"}],
    )
    cluster_id = resp["JobFlowId"]
    ctx.on_cleanup(lambda: emr.terminate_job_flows(JobFlowIds=[cluster_id]))
    return cluster_id


def _launch_cluster_with_retry(
    ctx, roles: dict[str, str], subnet_id: str, configurations: list, bucket: str, timeout_s: float = 180.0
) -> str:
    deadline = time.monotonic() + timeout_s
    last_err: Exception | None = None
    while time.monotonic() < deadline:
        try:
            return _launch_cluster(ctx, roles, subnet_id, configurations, bucket)
        except ClientError as err:
            last_err = err
            if err.response["Error"]["Code"] == "ValidationException":
                time.sleep(2)
                continue
            raise
    assert last_err is not None, "retry loop exited without a captured ClientError to re-raise"
    raise last_err


def _wait_for_cluster_ready(ctx, cluster_id: str, timeout_s: float = 1200.0) -> None:
    emr = ctx.client("emr")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        state = emr.describe_cluster(ClusterId=cluster_id)["Cluster"]["Status"]["State"]
        if state == "WAITING":
            return
        if state in ("TERMINATED", "TERMINATED_WITH_ERRORS"):
            raise AssertionError(f"cluster {cluster_id} reached terminal state {state} before becoming ready")
        time.sleep(2)
    raise AssertionError(f"cluster {cluster_id} did not become ready within {timeout_s}s")


def _wait_for_step(ctx, cluster_id: str, step_id: str, timeout_s: float = 900.0) -> str:
    emr = ctx.client("emr")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        state = emr.describe_step(ClusterId=cluster_id, StepId=step_id)["Step"]["Status"]["State"]
        if state in ("COMPLETED", "FAILED", "CANCELLED", "INTERRUPTED"):
            return state
        time.sleep(2)
    raise AssertionError(f"step {step_id} did not reach a terminal state within {timeout_s}s")


def _run_shell_step(ctx, cluster_id: str, name: str, script: str) -> tuple[str, str]:
    emr = ctx.client("emr")
    resp = emr.add_job_flow_steps(
        JobFlowId=cluster_id,
        Steps=[
            {
                "Name": name,
                "ActionOnFailure": "CONTINUE",
                "HadoopJarStep": {"Jar": "command-runner.jar", "Args": ["bash", "-c", script]},
            }
        ],
    )
    step_id = resp["StepIds"][0]
    state = _wait_for_step(ctx, cluster_id, step_id)
    return step_id, state


# ===== private network =====
#: The check's own VPC: its clusters sit in a subnet with no internet route; a gateway endpoint to
#: S3 and an interface endpoint to Glue (the metastore the cluster calls) are the only ways out.
_PRIVATE_VPC_CIDR = "10.0.0.0/16"
_PRIVATE_SUBNET_CIDR = "10.0.0.0/24"
#: The suite's cleanup budget: one deadline per run, started by the first teardown that asks for
#: it; every teardown wait of the run is cut to it.
_CLEANUP_BUDGET_S = 900.0
_cleanup_deadlines: dict[int, tuple[object, float]] = {}
_CLUSTERS: dict[int, tuple[object, set[str]]] = {}
_NETWORK_RETRY = frozenset({
    "DependencyViolation", "InvalidGroup.NotFound", "InvalidPermission.NotFound",
    "InvalidSubnetID.NotFound", "InvalidNetworkInterfaceID.NotFound",
})
_NETWORKS: dict[int, tuple[object, tuple[str, str]]] = {}


def _private_network(ctx, instance_type: str = "m5.xlarge") -> tuple[str, str]:
    """(vpc_id, subnet_id) of this check's private network, created on first use in a zone that
    offers instance_type, its Glue endpoint available; its teardown is registered before any
    cluster is placed in it."""
    hit = _NETWORKS.get(id(ctx))
    if hit is not None and hit[0] is ctx:
        return hit[1]
    ec2 = ctx.client("ec2")
    zones = sorted(z["ZoneName"] for z in ec2.describe_availability_zones(
        Filters=[{"Name": "state", "Values": ["available"]},
                 {"Name": "zone-type", "Values": ["availability-zone"]}])["AvailabilityZones"])
    offered = {o["Location"] for o in ec2.describe_instance_type_offerings(
        LocationType="availability-zone",
        Filters=[{"Name": "instance-type", "Values": [instance_type]},
                 {"Name": "location", "Values": zones}])["InstanceTypeOfferings"]}
    usable = [z for z in zones if z in offered]
    assert usable, f"no available zone offers {instance_type}: zones {zones!r}"
    tags = [{"Key": "sim2real:managed", "Value": "true"}]
    vpc_id = ec2.create_vpc(CidrBlock=_PRIVATE_VPC_CIDR, TagSpecifications=[
        {"ResourceType": "vpc", "Tags": tags}])["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _drop_private_network(ctx, vpc_id))
    ctx.client("emr").meta.events.register(
        "after-call.emr.RunJobFlow", lambda parsed, **_: _track_cluster(ctx, parsed.get("JobFlowId")))
    ec2.get_waiter("vpc_available").wait(VpcIds=[vpc_id], WaiterConfig={"Delay": 2, "MaxAttempts": 30})
    ec2.modify_vpc_attribute(VpcId=vpc_id, EnableDnsHostnames={"Value": True})
    subnet_id = ec2.create_subnet(
        VpcId=vpc_id, CidrBlock=_PRIVATE_SUBNET_CIDR, AvailabilityZone=usable[0],
        TagSpecifications=[{"ResourceType": "subnet", "Tags": tags}])["Subnet"]["SubnetId"]
    table = ec2.describe_route_tables(Filters=[
        {"Name": "vpc-id", "Values": [vpc_id]},
        {"Name": "association.main", "Values": ["true"]}])["RouteTables"][0]["RouteTableId"]
    ec2.create_vpc_endpoint(
        VpcId=vpc_id, VpcEndpointType="Gateway", RouteTableIds=[table],
        ServiceName=f"com.amazonaws.{ec2.meta.region_name}.s3",
        TagSpecifications=[{"ResourceType": "vpc-endpoint", "Tags": tags}])
    group = ec2.create_security_group(
        GroupName=ctx.unique_name("sim2real-emr-glue-endpoint-"), VpcId=vpc_id,
        Description="HTTPS from the VPC to the Glue endpoint",
        TagSpecifications=[{"ResourceType": "security-group", "Tags": tags}])["GroupId"]
    ec2.authorize_security_group_ingress(GroupId=group, IpPermissions=[{
        "IpProtocol": "tcp", "FromPort": 443, "ToPort": 443,
        "IpRanges": [{"CidrIp": _PRIVATE_VPC_CIDR}]}])
    endpoint = ec2.create_vpc_endpoint(
        VpcId=vpc_id, VpcEndpointType="Interface", SubnetIds=[subnet_id], SecurityGroupIds=[group],
        ServiceName=f"com.amazonaws.{ec2.meta.region_name}.glue", PrivateDnsEnabled=True,
        TagSpecifications=[{"ResourceType": "vpc-endpoint", "Tags": tags}])["VpcEndpoint"]["VpcEndpointId"]
    deadline = time.monotonic() + min(300.0, ctx.time_left() or 300.0)
    while True:
        state = ec2.describe_vpc_endpoints(VpcEndpointIds=[endpoint])["VpcEndpoints"][0]["State"]
        if state.lower() == "available":
            break
        assert state.lower() == "pending" and time.monotonic() < deadline, (
            f"Glue endpoint {endpoint} is {state!r}, not available")
        time.sleep(2)
    _NETWORKS[id(ctx)] = (ctx, (vpc_id, subnet_id))
    return vpc_id, subnet_id


def _cleanup_deadline(ctx) -> float:
    """The run's one teardown deadline, started by the first teardown that asks for it."""
    hit = _cleanup_deadlines.get(id(ctx))
    if hit is None or hit[0] is not ctx:
        hit = _cleanup_deadlines[id(ctx)] = (ctx, time.monotonic() + _CLEANUP_BUDGET_S)
    return hit[1]


def _track_cluster(ctx, cluster_id) -> None:
    """Record a cluster this check created, so the network teardown waits for it to terminate."""
    if cluster_id:
        hit = _CLUSTERS.get(id(ctx))
        if hit is None or hit[0] is not ctx:
            hit = _CLUSTERS[id(ctx)] = (ctx, set())
        hit[1].add(cluster_id)


def _drop_private_network(ctx, vpc_id: str) -> None:
    """Delete the check's VPC: wait for its EMR clusters to terminate, delete its endpoints, wait for
    its interfaces to release, clear then delete every non-default group (EMR's reference each other),
    route tables, subnets, the VPC. Retries in-use refusals every 2 s to the run's cleanup deadline."""
    from botocore.exceptions import ClientError

    _NETWORKS.pop(id(ctx), None)
    tracked = _CLUSTERS.pop(id(ctx), (ctx, set()))
    created = tracked[1] if tracked[0] is ctx else set()
    ec2 = ctx.client("ec2")
    emr = ctx.client("emr")
    in_vpc = [{"Name": "vpc-id", "Values": [vpc_id]}]
    deadline = _cleanup_deadline(ctx)

    def _emr_state(cluster_id: str) -> str:
        try:
            return emr.describe_cluster(ClusterId=cluster_id)["Cluster"]["Status"]["State"]
        except ClientError as exc:
            err = exc.response["Error"]
            message = err.get("Message", "").lower()
            if err["Code"] == "ClusterNotFound" or (
                    err["Code"] == "InvalidRequestException"
                    and ("not found" in message or "is not valid" in message)):
                return "TERMINATED"
            raise

    def _teardown_pass() -> str:
        """One pass: what the VPC still waits on, or "" once it is deleted."""
        clusters = sorted(created | {t["Value"] for r in ec2.describe_instances(Filters=in_vpc)["Reservations"]
                                     for i in r["Instances"] for t in i.get("Tags", [])
                                     if t["Key"] == "aws:elasticmapreduce:job-flow-id"})
        for cluster_id in clusters:
            state = _emr_state(cluster_id)
            if state not in ("TERMINATED", "TERMINATED_WITH_ERRORS"):
                return f"cluster {cluster_id} is {state}"
        endpoints = [e for e in ec2.describe_vpc_endpoints(Filters=in_vpc)["VpcEndpoints"]
                     if e["State"].lower() != "deleted"]
        live = [e["VpcEndpointId"] for e in endpoints if e["State"].lower() != "deleting"]
        if live:
            failed = [u for u in ec2.delete_vpc_endpoints(VpcEndpointIds=live).get("Unsuccessful", [])
                      if u["Error"]["Code"] != "InvalidVpcEndpointId.NotFound"]
            if failed:
                raise RuntimeError(f"VPC endpoints of {vpc_id} not deleted: {failed!r}")
        if endpoints:
            return f"endpoints {[e['VpcEndpointId'] for e in endpoints]!r} are deleting"
        interfaces = ec2.describe_network_interfaces(Filters=in_vpc)["NetworkInterfaces"]
        attached = [n["NetworkInterfaceId"] for n in interfaces if n["Status"] != "available"]
        if attached:
            return f"interfaces {attached!r} are still attached"
        for n in interfaces:
            ec2.delete_network_interface(NetworkInterfaceId=n["NetworkInterfaceId"])
        groups = [g for g in ec2.describe_security_groups(Filters=in_vpc)["SecurityGroups"]
                  if g["GroupName"] != "default"]
        for g in groups:
            if g.get("IpPermissions"):
                ec2.revoke_security_group_ingress(GroupId=g["GroupId"], IpPermissions=g["IpPermissions"])
            if g.get("IpPermissionsEgress"):
                ec2.revoke_security_group_egress(
                    GroupId=g["GroupId"], IpPermissions=g["IpPermissionsEgress"])
        for g in groups:
            ec2.delete_security_group(GroupId=g["GroupId"])
        for table in ec2.describe_route_tables(Filters=in_vpc)["RouteTables"]:
            associations = table.get("Associations", [])
            if any(a.get("Main") for a in associations):
                continue
            for a in associations:
                ec2.disassociate_route_table(AssociationId=a["RouteTableAssociationId"])
            ec2.delete_route_table(RouteTableId=table["RouteTableId"])
        for s in ec2.describe_subnets(Filters=in_vpc)["Subnets"]:
            ec2.delete_subnet(SubnetId=s["SubnetId"])
        ec2.delete_vpc(VpcId=vpc_id)
        return ""

    while True:
        try:
            waiting = _teardown_pass()
            if not waiting:
                return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "InvalidVpcID.NotFound":
                return
            if code not in _NETWORK_RETRY:
                raise RuntimeError(f"VPC {vpc_id} teardown: {exc}") from exc
            waiting = str(exc)
        if time.monotonic() >= deadline:
            raise RuntimeError(f"VPC {vpc_id} teardown missed the cleanup deadline: {waiting}")
        time.sleep(2)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
