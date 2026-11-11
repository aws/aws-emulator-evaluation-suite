"""parameter-group-update-reflects-on-cluster."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "parameter-group-update-reflects-on-cluster"
GROUP = "state-machine"
SERVICES = ["dax"]

_NODE_TYPE = "dax.t3.small"
_TIMEOUT_S = 1500.0


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateParameterGroup on a group attached to a running cluster shows the new value with a non-system
    Source, and the cluster's ParameterGroup converges on that group with no NodeIdsToReboot for an
    IMMEDIATE-change parameter."""
    dax = ctx.client("dax")
    pg_name = ctx.unique_name("sim2real-dax-pg-")
    dax.create_parameter_group(ParameterGroupName=pg_name)
    ctx.on_cleanup(lambda: _safe_delete_parameter_group(ctx, pg_name))

    defaults = _list_all(ctx, lambda **kw: dax.describe_default_parameters(**kw), "Parameters")
    param_name, new_value, _source, _old_value = _pick_immediate_integer_param(defaults)

    role_arn = _create_dax_service_role(ctx)
    subnet_ids = _default_vpc_subnet_ids(ctx, count=2)
    subnet_group_name = _create_subnet_group(ctx, subnet_ids)
    cluster_name = ctx.unique_name("sim2real-dax-cl-")

    _create_cluster_with_retry(
        ctx,
        ClusterName=cluster_name,
        NodeType=_NODE_TYPE,
        ReplicationFactor=1,
        IamRoleArn=role_arn,
        SubnetGroupName=subnet_group_name,
        ParameterGroupName=pg_name,
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _safe_delete_cluster(ctx, cluster_name))
    _poll_until(
        lambda: _describe_cluster(ctx, cluster_name),
        lambda c: c["Status"] == "available",
        timeout_s=_TIMEOUT_S,
    )

    dax.update_parameter_group(
        ParameterGroupName=pg_name,
        ParameterNameValues=[{"ParameterName": param_name, "ParameterValue": str(new_value)}],
    )

    group_params = _list_all(ctx, lambda **kw: dax.describe_parameters(ParameterGroupName=pg_name, **kw), "Parameters")
    updated_param = next(p for p in group_params if p["ParameterName"] == param_name)
    assert updated_param["ParameterValue"] == str(new_value), (
        f"expected DescribeParameters to reflect {param_name}={new_value!r}, "
        f"got {updated_param['ParameterValue']!r}"
    )
    assert updated_param["Source"] != "system", (
        f"expected {param_name} Source to be non-system after an explicit update, got {updated_param['Source']!r}"
    )

    settled = _poll_until(
        lambda: _describe_cluster(ctx, cluster_name),
        lambda c: c["ParameterGroup"]["ParameterApplyStatus"] == "in-sync",
        timeout_s=_TIMEOUT_S,
    )
    assert settled["ParameterGroup"]["ParameterGroupName"] == pg_name, (
        f"expected cluster to still reference parameter group {pg_name!r}, "
        f"got {settled['ParameterGroup']['ParameterGroupName']!r}"
    )
    assert not settled["ParameterGroup"].get("NodeIdsToReboot"), (
        "expected an IMMEDIATE-change parameter update to require no reboot, "
        f"but NodeIdsToReboot={settled['ParameterGroup'].get('NodeIdsToReboot')!r}"
    )


def _cluster_gone(dax, cluster_name):
    """Existence probe: True once DescribeClusters reports ClusterNotFoundFault."""
    try:
        dax.describe_clusters(ClusterNames=[cluster_name])
    except ClientError as err:
        return err.response["Error"]["Code"] == "ClusterNotFoundFault"
    return False


def _describe_cluster(ctx, cluster_name):
    return ctx.client("dax").describe_clusters(ClusterNames=[cluster_name])["Clusters"][0]


def _poll_until(probe, predicate, timeout_s, interval_s=20.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last observed={last!r}")


def _list_all(ctx, call, field):
    out = []
    token = None
    while True:
        kwargs = {"NextToken": token} if token else {}
        resp = call(**kwargs)
        out.extend(resp[field])
        token = resp.get("NextToken")
        if not token:
            break
    return out


def _pick_immediate_integer_param(parameters):
    """DAX's real AllowedValues for its two modifiable parameters is the open-ended
    "0-" (a floor with no ceiling), not a closed "lo-hi" range -- so the upper bound
    is absent rather than parseable, and only the lower bound is ever required."""
    for p in parameters:
        if p.get("IsModifiable") != "TRUE" or p.get("ChangeType") != "IMMEDIATE":
            continue
        allowed = p.get("AllowedValues") or ""
        if "-" not in allowed:
            continue
        lo_s, _, hi_s = allowed.partition("-")
        try:
            lo = int(lo_s)
            hi = int(hi_s) if hi_s else None
            current = int(p["ParameterValue"])
        except ValueError:
            continue
        candidate = current + 1 if hi is None or current + 1 <= hi else max(lo, current - 1)
        if candidate == current:
            continue
        return p["ParameterName"], candidate, p.get("Source"), p["ParameterValue"]
    raise AssertionError(
        "no customer-modifiable IMMEDIATE-apply numeric-range DAX parameter found via "
        "DescribeDefaultParameters to exercise UpdateParameterGroup"
    )


def _safe_delete_parameter_group(ctx, name):
    try:
        ctx.client("dax").delete_parameter_group(ParameterGroupName=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "ParameterGroupNotFoundFault",
            "ServiceLinkedRoleNotFoundFault",
        ):
            raise


def _default_vpc_subnet_ids(ctx, count=2):
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError("no shared network VPC available in this account/region for DAX subnet group creation")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    if len(subnets) < count:
        raise AssertionError(f"shared network has fewer than {count} subnets available")
    return [s["SubnetId"] for s in subnets[:count]]


def _create_subnet_group(ctx, subnet_ids):
    dax = ctx.client("dax")
    name = ctx.unique_name("sim2real-dax-sng-")
    dax.create_subnet_group(SubnetGroupName=name, SubnetIds=subnet_ids)
    ctx.on_cleanup(lambda: _safe_delete_subnet_group(ctx, name))
    return name


def _safe_delete_subnet_group(ctx, name):
    try:
        ctx.client("dax").delete_subnet_group(SubnetGroupName=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "ServiceLinkedRoleNotFoundFault",
            "SubnetGroupNotFoundFault",
        ):
            raise


def _create_dax_service_role(ctx):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-dax-role-")
    trust_policy = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Principal": {"Service": "dax.amazonaws.com"}, "Action": "sts:AssumeRole"}
            ],
        }
    )
    access_policy = json.dumps(
        {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "dynamodb:*", "Resource": "*"}]}
    )
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=trust_policy,
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )["Role"]
    iam.put_role_policy(RoleName=role_name, PolicyName="dax-dynamodb-access", PolicyDocument=access_policy)

    def _cleanup():
        try:
            iam.delete_role_policy(RoleName=role_name, PolicyName="dax-dynamodb-access")
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
        try:
            iam.delete_role(RoleName=role_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise

    ctx.on_cleanup(_cleanup)
    return role["Arn"]


def _create_cluster_with_retry(ctx, timeout_s=60.0, interval_s=5.0, **kwargs):
    """CreateCluster can reject a just-created role until its IAM trust policy
    propagates; retry the call itself instead of guessing a fixed delay."""
    dax = ctx.client("dax")
    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            return dax.create_cluster(**kwargs)["Cluster"]
        except ClientError as err:
            last_err = err
            time.sleep(interval_s)
    raise AssertionError(f"create_cluster did not succeed within {timeout_s}s; last error={last_err}")


def _safe_delete_cluster(ctx, cluster_name, timeout_s=_TIMEOUT_S):
    dax = ctx.client("dax")
    if _cluster_gone(dax, cluster_name):
        return
    try:
        _poll_until(
            lambda: _describe_cluster(ctx, cluster_name),
            lambda c: c["Status"] == "available",
            timeout_s=timeout_s,
        )
    except AssertionError:
        pass
    try:
        dax.delete_cluster(ClusterName=cluster_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "ClusterNotFoundFault",
            "ServiceLinkedRoleNotFoundFault",
        ):
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
