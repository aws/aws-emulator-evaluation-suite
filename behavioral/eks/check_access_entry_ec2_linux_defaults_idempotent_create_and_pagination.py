"""access-entry-ec2-linux-defaults-idempotent-create-and-pagination."""
from __future__ import annotations

import json
import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "access-entry-ec2-linux-defaults-idempotent-create-and-pagination"
GROUP = "representation"
SERVICES = ["eks"]

PREFIX = "sim2real-behav-"
CLUSTER_ROLE = PREFIX + "eks-cluster-role"
_EKS_CLUSTER_POLICY = "arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"
_BAD_AZS = {"use1-az3", "usw1-az2", "usw2-az4", "cac1-az3", "cac1-az4"}


def _error_code(fn):
    """Call fn, require it raises ClientError, return the error Code."""
    try:
        fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"]
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
            Tags=[{"Key": "sim2real", "Value": "1"}],
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


def _retry_role_propagation(fn, timeout_s=120, interval_s=6, desc=""):
    """Retry fn() through the window where EKS still rejects a just-created IAM role as
    unrecognized (InvalidParameterException) because IAM is eventually consistent."""
    deadline = time.time() + timeout_s
    last_exc = None
    while time.time() < deadline:
        try:
            return fn()
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "InvalidParameterException":
                raise
            last_exc = exc
            time.sleep(interval_s)
    raise AssertionError(f"{desc} kept failing on IAM propagation lag after {timeout_s}s: {last_exc}")


def _principal_role(ctx, label="eks-principal-"):
    """A fresh, IAM-propagated throwaway principal EKS will accept."""
    name = ctx.unique_name(PREFIX + label)
    arn = _ensure_role(ctx, name, "ec2.amazonaws.com")
    ctx.on_cleanup(lambda: ctx.client("iam").delete_role(RoleName=name))
    return arn


def _subnet_ids(ctx):
    """Two subnets in two distinct, EKS-supported AZs of the run's shared network."""
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
    _retry_role_propagation(
        lambda: c.create_cluster(
            name=name,
            roleArn=role_arn,
            resourcesVpcConfig={
                "subnetIds": _subnet_ids(ctx),
                "endpointPublicAccess": True,
                "endpointPrivateAccess": False,
            },
            accessConfig={
                "authenticationMode": "API_AND_CONFIG_MAP",
                "bootstrapClusterCreatorAdminPermissions": True,
            },
        ),
        desc=f"create_cluster {name}",
    )
    ctx.on_cleanup(lambda: c.delete_cluster(name=name))
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


def _list_all_access_entries(c, cluster_name, page_size=1, page_limit=200):
    """Walk ListAccessEntries at maxResults=page_size, asserting each page respects the size;
    return every principalArn seen."""
    seen: list[str] = []
    token = None
    for _ in range(page_limit):
        kwargs = {"clusterName": cluster_name, "maxResults": page_size}
        if token:
            kwargs["nextToken"] = token
        page = c.list_access_entries(**kwargs)
        entries = page.get("accessEntries", [])
        assert len(entries) <= page_size, (
            f"ListAccessEntries(maxResults={page_size}) returned {len(entries)} entries, "
            f"more than requested: {entries!r}"
        )
        seen.extend(entries)
        token = page.get("nextToken")
        if not token:
            return seen
    raise AssertionError(f"ListAccessEntries did not terminate within {page_limit} pages")


@tags("axis:happy-path", "cap:c2", "concern:representation", "plane:control")
def run(ctx) -> None:
    """An EC2_LINUX access entry gets the server-derived node username and system:nodes group and
    keeps its tags; a retry with the same clientRequestToken returns the same ARN; and a
    maxResults=1 ListAccessEntries walk surfaces both principals exactly once.
    """
    c = ctx.client("eks")
    cluster = _active_cluster(ctx, c, "eks-aedef-")
    first = _principal_role(ctx, "aedef-a-")
    second = _principal_role(ctx, "aedef-b-")

    # ClientRequestToken must be 33-126 characters; unique_name() alone is too short.
    token = ctx.unique_name("sim2real-sdk-retry-") + "-" + uuid.uuid4().hex
    create_kwargs = dict(
        clusterName=cluster,
        principalArn=first,
        type="EC2_LINUX",
        tags={"team": "platform"},
        clientRequestToken=token,
    )
    created = _retry_role_propagation(
        lambda: c.create_access_entry(**create_kwargs)["accessEntry"],
        desc="create_access_entry(EC2_LINUX)",
    )
    ctx.on_cleanup(lambda: c.delete_access_entry(clusterName=cluster, principalArn=first))
    assert created["username"] == "system:node:{{EC2PrivateDNSName}}", (
        f"EC2_LINUX access entries must get the server-derived node username; got "
        f"{created['username']!r}"
    )
    assert created["kubernetesGroups"] == ["system:nodes"], (
        f"EC2_LINUX access entries must get the server-derived group ['system:nodes']; "
        f"got {created['kubernetesGroups']!r}"
    )
    assert created.get("createdAt") is not None, f"createdAt must be set; got {created!r}"
    assert created.get("tags") == {"team": "platform"}, (
        f"the tags supplied at create must round-trip onto the entry unchanged; got "
        f"{created.get('tags')!r}"
    )

    retried = c.create_access_entry(**create_kwargs)["accessEntry"]
    assert retried["accessEntryArn"] == created["accessEntryArn"], (
        f"retrying CreateAccessEntry with the SAME clientRequestToken and parameters must "
        f"be idempotent and return the SAME accessEntryArn, not create or reject a second "
        f"one; first={created['accessEntryArn']!r}, retry={retried['accessEntryArn']!r}"
    )

    described = c.describe_access_entry(clusterName=cluster, principalArn=first)["accessEntry"]
    assert described["principalArn"] == first, (
        f"DescribeAccessEntry must report the principal it was asked about; got "
        f"{described['principalArn']!r}"
    )

    _retry_role_propagation(
        lambda: c.create_access_entry(clusterName=cluster, principalArn=second),
        desc="create_access_entry(second principal)",
    )
    ctx.on_cleanup(lambda: c.delete_access_entry(clusterName=cluster, principalArn=second))

    all_entries = _list_all_access_entries(c, cluster, page_size=1)
    assert first in all_entries, (
        f"the paginated walk at maxResults=1 must surface {first!r}; saw {all_entries!r}"
    )
    assert second in all_entries, (
        f"the paginated walk at maxResults=1 must surface {second!r}; saw {all_entries!r}"
    )
    assert all_entries.count(first) == 1 and all_entries.count(second) == 1, (
        f"each principal must appear exactly once across the paginated walk, not "
        f"duplicated across pages; saw {all_entries!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
