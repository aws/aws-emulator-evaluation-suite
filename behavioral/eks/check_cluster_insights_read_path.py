"""cluster-insights-read-path."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cluster-insights-read-path"
GROUP = 'data-plane'
SERVICES = ['eks']

PREFIX = "sim2real-behav-"
CLUSTER_ROLE = PREFIX + "eks-cluster-role"
_EKS_CLUSTER_POLICY = "arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"
_BAD_AZS = {"use1-az3", "usw1-az2", "usw2-az4", "cac1-az3", "cac1-az4"}


def _error(fn):
    """Call fn, require it raises ClientError, return the error (Code, Message)."""
    try:
        fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError("expected the call to fail, but it succeeded")


def _trust(service, extra_actions=()):
    return json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Service": service},
                    "Action": ["sts:AssumeRole", *extra_actions],
                }
            ],
        }
    )


def _ensure_role(ctx, name, service="eks.amazonaws.com", managed_policies=()):
    """Create-or-reuse an IAM role and return its ARN."""
    iam = ctx.client("iam")
    try:
        arn = iam.create_role(
            RoleName=name,
            AssumeRolePolicyDocument=_trust(service),
            Description="SimParityProbe EKS behavioral fidelity fixture",
        )["Role"]["Arn"]
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        if code == "EntityAlreadyExists":
            arn = iam.get_role(RoleName=name)["Role"]["Arn"]
        elif code in ("AccessDenied", "AccessDeniedException"):
            raise AssertionError(f"probe identity cannot create IAM role {name}: {exc}") from exc
        else:
            raise
    for policy_arn in managed_policies:
        try:
            iam.attach_role_policy(RoleName=name, PolicyArn=policy_arn)
        except ClientError:
            pass
    return arn


def _retry_role_propagation(fn, timeout_s=90, interval_s=5):
    """Retry fn() while EKS still reports the role unusable; IAM's propagation lag
    is bounded, not instantaneous, so give it a deadline instead of a fixed sleep."""
    deadline = time.time() + timeout_s
    while True:
        try:
            return fn()
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            message = exc.response["Error"].get("Message", "")
            role_not_ready = code == "InvalidParameterException" and "role" in message.lower()
            if not role_not_ready or time.time() >= deadline:
                raise
            time.sleep(interval_s)


def _principal_role(ctx, label="eks-principal-"):
    """A fresh, IAM-propagated throwaway principal EKS will accept."""
    return _ensure_role(ctx, ctx.unique_name(PREFIX + label), "ec2.amazonaws.com")


def _subnet_ids(ctx):
    """Two subnets in two distinct, EKS-supported AZs of the shared network."""
    ec2 = ctx.client("ec2")
    resp = ec2.describe_subnets(Filters=[{"Name": "subnet-id", "Values": ctx.network().subnet_ids}])
    subnets = resp.get("Subnets", [])
    if not subnets:
        raise AssertionError(f"the run's shared network subnets {ctx.network().subnet_ids} are not visible")
    by_az: dict[str, str] = {}
    for sn in sorted(subnets, key=lambda s: s["AvailabilityZone"]):
        az = sn["AvailabilityZone"]
        if sn["AvailabilityZoneId"] in _BAD_AZS:
            continue
        by_az.setdefault(az, sn["SubnetId"])
    if len(by_az) < 2:
        raise AssertionError(f"need subnets in >=2 EKS-supported AZs, found {len(by_az)}")
    return [by_az[az] for az in sorted(by_az)][:2]


def _wait_for(fn, pred, timeout_s=300, interval_s=5, desc=""):
    deadline = time.time() + timeout_s
    while True:
        last = fn()
        if pred(last):
            return last
        if time.time() >= deadline:
            raise AssertionError(f"timed out after {timeout_s}s waiting for {desc}; last={last!r}")
        time.sleep(interval_s)


def _active_cluster(ctx, c, suffix):
    """Provision (create + wait ACTIVE) a throwaway cluster, register cleanup, return its name."""
    role_arn = _ensure_role(ctx, CLUSTER_ROLE, "eks.amazonaws.com", [_EKS_CLUSTER_POLICY])
    name = ctx.unique_name(PREFIX + suffix)
    subnet_ids = _subnet_ids(ctx)
    _retry_role_propagation(
        lambda: c.create_cluster(
            name=name,
            roleArn=role_arn,
            resourcesVpcConfig={
                "subnetIds": subnet_ids,
                "endpointPublicAccess": True,
                "endpointPrivateAccess": False,
            },
            accessConfig={
                "authenticationMode": "API_AND_CONFIG_MAP",
                "bootstrapClusterCreatorAdminPermissions": True,
            },
            tags={"sim2real": "1"},
        )
    )
    ctx.on_cleanup(lambda: _delete_eks_cluster_and_wait(c, name))
    resp = _wait_for(
        lambda: c.describe_cluster(name=name),
        lambda r: r["cluster"]["status"] in ("ACTIVE", "FAILED"),
        timeout_s=1500,
        interval_s=20,
        desc=f"cluster {name} status==ACTIVE",
    )
    cluster = resp["cluster"]
    assert cluster["status"] == "ACTIVE", f"cluster {name} landed in {cluster['status']!r}"
    return name

import uuid


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListInsights/DescribeInsight expose per-cluster upgrade insights and 404 on unknown ids."""
    c = ctx.client("eks")
    if not hasattr(c, "list_insights"):
        raise AssertionError("botocore in this environment exposes no eks.list_insights")
    cluster = _active_cluster(ctx, c, "eks-ins-")

    insights = c.list_insights(clusterName=cluster)["insights"]
    assert isinstance(insights, list), insights
    unknown_id = str(uuid.uuid4())
    unknown_id_code, unknown_id_msg = _error(lambda: c.describe_insight(clusterName=cluster, id=unknown_id))
    assert unknown_id_code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException for an unknown insight id, got {unknown_id_code!r}"
    )
    # The message embeds the cluster's internal id and a backend request id the check never
    # sees; the text around them is asserted.
    assert unknown_id_msg.startswith(f"Cannot find insight insightId={unknown_id} clusterId=") and (
        " (Service: EksClusterInsights, Status Code: 404, Request ID: " in unknown_id_msg
    ) and unknown_id_msg.endswith(") (SDK Attempt Count: 1)"), unknown_id_msg
    absent = ctx.unique_name("absent-clu-")
    unknown_cluster_code, unknown_cluster_msg = _error(lambda: c.list_insights(clusterName=absent))
    assert unknown_cluster_code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException for an unknown cluster, got {unknown_cluster_code!r}"
    )
    assert unknown_cluster_msg == f"No cluster found for name: {absent}.", unknown_cluster_msg

    if insights:
        summary = insights[0]
        detail = c.describe_insight(clusterName=cluster, id=summary["id"])["insight"]
        assert detail["id"] == summary["id"], detail
        assert detail["category"] == summary["category"], detail
        # The status is a 4-value enum, so membership alone can never fail; the
        # summary and the detail must agree on the *same* value.
        assert detail["insightStatus"]["status"] == summary["insightStatus"]["status"], (
            detail["insightStatus"],
            summary["insightStatus"],
        )

    if hasattr(c, "start_insights_refresh"):
        try:
            refresh = c.start_insights_refresh(clusterName=cluster)
            # A freshly issued on-demand refresh has not had time to complete: it
            # reports IN_PROGRESS, not any of the other two terminal enum values.
            assert refresh.get("status") == "IN_PROGRESS", refresh
        except ClientError as exc:
            # Insights are not wired up for the first ~15 minutes of a cluster's life.
            assert exc.response["Error"]["Code"] == "ResourceNotFoundException", exc.response["Error"]
            message = exc.response["Error"].get("Message", "")
            # The message ends in a backend request id the check never sees.
            assert message.startswith(
                "The cluster isn't available yet for cluster insights. Wait up to 15 minutes and try "
                "again. (Service: EksClusterInsights, Status Code: 404, Request ID: "
            ) and message.endswith(") (SDK Attempt Count: 1)"), message



def _delete_eks_cluster_and_wait(eks, name, timeout_s=1200.0, interval_s=20.0):
    """Delete an EKS cluster and wait until it is gone, so its ENIs leave the shared network.

    DeleteCluster is refused while an update, node group or add-on operation still runs; that
    ResourceInUseException is retried until the deadline.
    """
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            eks.delete_cluster(name=name)
            break
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code == "ResourceNotFoundException":
                return
            if code != "ResourceInUseException" or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)
    while time.monotonic() < deadline:
        try:
            eks.describe_cluster(name=name)
        except ClientError as e:
            if e.response["Error"]["Code"] == "ResourceNotFoundException":
                return
            raise
        time.sleep(interval_s)
    raise AssertionError(f"EKS cluster {name} still exists {timeout_s:.0f}s after DeleteCluster")

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
