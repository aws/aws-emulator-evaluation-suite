"""start-job-run-spark-pi-native-round-trip."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "start-job-run-spark-pi-native-round-trip"
GROUP = "native-protocol"
SERVICES = ["emr-containers"]

CLUSTER_ACTIVE_TIMEOUT_S = 1200
CLUSTER_DELETE_TIMEOUT_S = 900
NODEGROUP_ACTIVE_TIMEOUT_S = 900
NODEGROUP_DELETE_TIMEOUT_S = 900
VC_REACHABLE_TIMEOUT_S = 420
JOB_RUN_TIMEOUT_S = 900
RELEASE_LABEL = "emr-6.15.0-latest"


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """StartJobRun runs the bundled SparkPi example on the EKS compute to COMPLETED, with
    finishedAt after createdAt: the job must really run, not just be accepted."""
    emrc = ctx.client("emr-containers")
    cluster_id, namespace, execution_role_arn = _job_run_fixture(ctx)

    vc = _create_virtual_cluster(
        emrc,
        name=ctx.unique_name("sim2real-vc-"),
        clientToken=ctx.unique_name("tok-"),
        containerProvider={
            "type": "EKS",
            "id": cluster_id,
            "info": {"eksInfo": {"namespace": namespace}},
        },
        tags={"sim2real-check": CHECK},
    )
    vc_id = vc["id"]
    ctx.on_cleanup(lambda: _delete_vc_ignore(emrc, vc_id))

    job = emrc.start_job_run(
        name=ctx.unique_name("sim2real-jr-"),
        virtualClusterId=vc_id,
        clientToken=ctx.unique_name("tok-"),
        executionRoleArn=execution_role_arn,
        releaseLabel=RELEASE_LABEL,
        jobDriver={
            "sparkSubmitJobDriver": {
                "entryPoint": "local:///usr/lib/spark/examples/jars/spark-examples.jar",
                "sparkSubmitParameters": (
                    "--class org.apache.spark.examples.SparkPi --conf "
                    "spark.executor.instances=1 --conf spark.executor.memory=1G "
                    "--conf spark.driver.memory=1G --conf spark.executor.cores=1"
                ),
            }
        },
        tags={"sim2real-check": CHECK},
    )
    job_id = job["id"]
    ctx.on_cleanup(lambda: _cancel_ignore(emrc, vc_id, job_id))

    final = _poll_until(
        lambda: emrc.describe_job_run(id=job_id, virtualClusterId=vc_id)["jobRun"],
        lambda jr: jr["state"] in ("COMPLETED", "FAILED", "CANCELLED"),
        timeout_s=JOB_RUN_TIMEOUT_S,
        interval_s=15,
    )
    assert final["state"] == "COMPLETED", (
        f"SparkPi job run did not COMPLETE: state={final['state']} "
        f"details={final.get('stateDetails')} failureReason={final.get('failureReason')}"
    )
    assert final["finishedAt"] > final["createdAt"], (
        f"finishedAt={final['finishedAt']} not after createdAt={final['createdAt']}"
    )


def _job_run_fixture(ctx):
    """Create an EKS cluster with a two-node managed node group in the shared network, its IAM
    OIDC provider, and a job execution role trusted by EMR on EKS service accounts in the
    namespace; return (cluster, namespace, execution role ARN).

    On an API-auth cluster EMR on EKS registers its own access entry and the node group
    registers its node role, so the job can run with no kubectl step.
    """
    from botocore.exceptions import ClientError

    ec2 = ctx.client("ec2")
    iam = ctx.client("iam")
    eks = ctx.client("eks")
    namespace = "default"
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    assert vpcs, "the account has no shared network VPC to host the EKS cluster"
    subnets = ec2.describe_subnets(
        Filters=[{"Name": "vpc-id", "Values": [vpcs[0]["VpcId"]]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}]
    )["Subnets"]
    by_az = {}
    for subnet in sorted(subnets, key=lambda s: s["AvailabilityZone"]):
        by_az.setdefault(subnet["AvailabilityZone"], subnet["SubnetId"])
    subnet_ids = list(by_az.values())[:3]
    assert len(subnet_ids) >= 2, f"the shared network spans fewer than two AZs: {by_az!r}"

    cluster_role = _create_role(
        ctx,
        iam,
        ctx.unique_name("sim2real-emrc-clusrole-"),
        {"Service": "eks.amazonaws.com"},
        "sts:AssumeRole",
        ["arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"],
    )
    node_role = _create_role(
        ctx,
        iam,
        ctx.unique_name("sim2real-emrc-noderole-"),
        {"Service": "ec2.amazonaws.com"},
        "sts:AssumeRole",
        [
            "arn:aws:iam::aws:policy/AmazonEKSWorkerNodePolicy",
            "arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly",
            "arn:aws:iam::aws:policy/AmazonEKS_CNI_Policy",
        ],
    )

    cluster_name = ctx.unique_name("sim2real-emrc-eks-")
    deadline = time.monotonic() + 60
    while True:
        try:
            eks.create_cluster(
                name=cluster_name,
                roleArn=cluster_role,
                resourcesVpcConfig={
                    "subnetIds": subnet_ids,
                    "endpointPublicAccess": True,
                    "endpointPrivateAccess": False,
                },
                accessConfig={"authenticationMode": "API_AND_CONFIG_MAP"},
            )
            break
        except ClientError as err:
            # A just-created cluster role is not yet assumable by EKS for a few seconds.
            if err.response["Error"]["Code"] != "InvalidParameterException":
                raise
            if time.monotonic() > deadline:
                raise
            time.sleep(5)
    ctx.on_cleanup(lambda: _delete_eks_cluster(eks, cluster_name))
    cluster = _wait_active(
        lambda: eks.describe_cluster(name=cluster_name)["cluster"],
        f"EKS cluster {cluster_name!r}",
        CLUSTER_ACTIVE_TIMEOUT_S,
    )

    nodegroup = ctx.unique_name("sim2real-emrc-ng-")
    eks.create_nodegroup(
        clusterName=cluster_name,
        nodegroupName=nodegroup,
        nodeRole=node_role,
        subnets=subnet_ids,
        instanceTypes=["m5.xlarge"],
        scalingConfig={"minSize": 2, "maxSize": 2, "desiredSize": 2},
    )
    ctx.on_cleanup(lambda: _delete_nodegroup(eks, cluster_name, nodegroup))

    issuer_host = cluster["identity"]["oidc"]["issuer"].replace("https://", "")
    provider_arn = iam.create_open_id_connect_provider(
        Url=f"https://{issuer_host}", ClientIDList=["sts.amazonaws.com"]
    )["OpenIDConnectProviderArn"]
    ctx.on_cleanup(
        lambda: iam.delete_open_id_connect_provider(OpenIDConnectProviderArn=provider_arn)
    )
    exec_name = ctx.unique_name("sim2real-emrc-exec-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Federated": provider_arn},
                "Action": "sts:AssumeRoleWithWebIdentity",
                "Condition": {
                    "StringLike": {
                        f"{issuer_host}:sub": (
                            f"system:serviceaccount:{namespace}:emr-containers-sa-*"
                        )
                    }
                },
            }
        ],
    }
    exec_arn = iam.create_role(RoleName=exec_name, AssumeRolePolicyDocument=json.dumps(trust))[
        "Role"
    ]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=exec_name))

    _wait_active(
        lambda: eks.describe_nodegroup(clusterName=cluster_name, nodegroupName=nodegroup)[
            "nodegroup"
        ],
        f"EKS node group {nodegroup!r}",
        NODEGROUP_ACTIVE_TIMEOUT_S,
    )
    return cluster_name, namespace, exec_arn


def _create_role(ctx, iam, role_name, principal, action, policy_arns):
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": principal, "Action": action}],
    }
    role_arn = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))[
        "Role"
    ]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    for policy_arn in policy_arns:
        iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
        ctx.on_cleanup(
            lambda p=policy_arn: iam.detach_role_policy(RoleName=role_name, PolicyArn=p)
        )
    return role_arn


def _wait_active(describe, label, timeout_s):
    deadline = time.monotonic() + timeout_s
    resource = describe()
    while resource["status"] != "ACTIVE":
        assert resource["status"] == "CREATING", f"{label} went {resource['status']!r}"
        if time.monotonic() > deadline:
            raise AssertionError(f"{label} still {resource['status']!r} at the deadline")
        time.sleep(2)
        resource = describe()
    return resource


def _delete_eks_cluster(eks, cluster_name) -> None:
    _delete_and_wait(
        lambda: eks.delete_cluster(name=cluster_name),
        lambda: eks.describe_cluster(name=cluster_name),
        f"EKS cluster {cluster_name!r}",
        CLUSTER_DELETE_TIMEOUT_S,
    )


def _delete_nodegroup(eks, cluster_name, nodegroup) -> None:
    _delete_and_wait(
        lambda: eks.delete_nodegroup(clusterName=cluster_name, nodegroupName=nodegroup),
        lambda: eks.describe_nodegroup(clusterName=cluster_name, nodegroupName=nodegroup),
        f"EKS node group {nodegroup!r}",
        NODEGROUP_DELETE_TIMEOUT_S,
    )


def _delete_and_wait(delete, describe, label, timeout_s) -> None:
    from botocore.exceptions import ClientError

    try:
        delete()
    except ClientError as err:
        if err.response["Error"]["Code"] != "ResourceNotFoundException":
            raise
        return
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            describe()
        except ClientError as err:
            if err.response["Error"]["Code"] == "ResourceNotFoundException":
                return
            raise
        time.sleep(2)
    raise AssertionError(f"{label} was not deleted within the deadline")


def _create_virtual_cluster(emrc, **kwargs):
    """CreateVirtualCluster, retried while EMR on EKS is still connecting to the new cluster.

    Right after the cluster turns ACTIVE, EMR reports it unreachable and then, until its own
    access entry takes effect, reports the namespace as missing; both clear within minutes.
    """
    from botocore.exceptions import ClientError

    namespace = kwargs["containerProvider"]["info"]["eksInfo"]["namespace"]
    transient = (
        "is not reachable as its connection is currently being updated",
        f"Required resource {namespace} not found on the cluster.",
    )
    deadline = time.monotonic() + VC_REACHABLE_TIMEOUT_S
    while True:
        try:
            return emrc.create_virtual_cluster(**kwargs)
        except ClientError as err:
            message = err.response["Error"].get("Message", "")
            if not any(t in message for t in transient) or time.monotonic() > deadline:
                raise
            time.sleep(2)


def _delete_vc_ignore(emrc, vc_id: str) -> None:
    from botocore.exceptions import ClientError

    try:
        emrc.delete_virtual_cluster(id=vc_id)
    except ClientError as err:
        # An already-deleted virtual cluster is refused; return only once it reads TERMINATED.
        if err.response["Error"]["Code"] != "ValidationException":
            raise
        try:
            state = emrc.describe_virtual_cluster(id=vc_id)["virtualCluster"]["state"]
        except ClientError as gone:
            if gone.response["Error"]["Code"] != "ResourceNotFoundException":
                raise
            return
        if state != "TERMINATED":
            raise


def _cancel_ignore(emrc, vc_id: str, job_id: str) -> None:
    from botocore.exceptions import ClientError

    try:
        emrc.cancel_job_run(id=job_id, virtualClusterId=vc_id)
    except ClientError as err:
        # A job run that already reached a terminal state is refused with exactly this error.
        error = err.response["Error"]
        expected = f"Job run {job_id} is not in a cancellable state"
        if (error["Code"], error.get("Message")) != ("ValidationException", expected):
            raise


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float):
    deadline = time.monotonic() + timeout_s
    value = probe()
    while time.monotonic() < deadline:
        value = probe()
        if predicate(value):
            return value
        time.sleep(interval_s)
    return value


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
