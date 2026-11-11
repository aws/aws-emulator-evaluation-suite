"""put-resource-policy-malformed-policy-rejected."""
from __future__ import annotations

import json
import secrets
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-resource-policy-malformed-policy-rejected"
GROUP = "data-plane"
SERVICES = ["redshift"]

_UNPARSEABLE_POLICY = "The resource policy can't be parsed."
_NO_POLICY = "The requested resource policy doesn\u2019t exist."

# Orderable node types vary by account (dc2 is not orderable in every account); cheapest
# single-node option, preferring the smallest, is discovered from the account itself.
# large-instance: last-resort fallback; the first orderable type in this order is used, so smaller types win
NODE_TYPE_PREFERENCE = ("dc2.large", "ra3.large", "ra3.xlplus", "dc2.8xlarge", "ra3.4xlarge")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutResourcePolicy rejects a syntactically-malformed policy document outright: the
    resource ends up with no policy attached at all (not a half-applied one), while a
    subsequent syntactically-valid Put on the very same resource still succeeds."""
    redshift = ctx.client("redshift")
    cluster = _create_available_cluster(ctx)

    # Break exactly one thing: syntactically invalid JSON for the Policy body.
    code, message = _error(
        lambda: redshift.put_resource_policy(
            ResourceArn=cluster["arn"], Policy="{not-valid-json: [oops"
        )
    )
    assert code == "InvalidPolicyFault", f"expected InvalidPolicyFault for malformed policy JSON, got {code!r}"
    assert message == _UNPARSEABLE_POLICY, f"unexpected InvalidPolicyFault message {message!r}"

    # Effect absent: no policy exists on the resource after the rejected Put.
    not_found_code, not_found_message = _error(
        lambda: redshift.get_resource_policy(ResourceArn=cluster["arn"])
    )
    assert not_found_code == "ResourceNotFoundFault", (
        f"expected ResourceNotFoundFault (no policy stored) after the rejected Put, got {not_found_code!r}"
    )
    assert not_found_message == _NO_POLICY, (
        f"unexpected ResourceNotFoundFault message {not_found_message!r}"
    )

    # Positive control in the same file, same resource: a well-formed policy still works.
    valid_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowSelfAccountInboundIntegration",
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:{cluster['partition']}:iam::{cluster['account']}:root"},
                "Action": "redshift:CreateInboundIntegration",
                "Resource": cluster["arn"],
            }
        ],
    }
    put_resp = redshift.put_resource_policy(ResourceArn=cluster["arn"], Policy=json.dumps(valid_policy))
    ctx.on_cleanup(lambda: redshift.delete_resource_policy(ResourceArn=cluster["arn"]))
    put_action = json.loads(put_resp["ResourcePolicy"]["Policy"])["Statement"][0]["Action"]
    assert put_action == "redshift:CreateInboundIntegration", (
        f"positive control: expected the same well-formed policy back from PutResourcePolicy, "
        f"got action {put_action!r}"
    )
    get_resp = redshift.get_resource_policy(ResourceArn=cluster["arn"])
    assert get_resp["ResourcePolicy"]["ResourceArn"] == cluster["arn"], (
        f"positive control: expected GetResourcePolicy to report ResourceArn={cluster['arn']!r}, "
        f"got {get_resp['ResourcePolicy'].get('ResourceArn')!r}"
    )


def _error(fn):
    """Call fn(); return botocore (Error.Code, Error.Message). An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _password() -> str:
    return "Sim2Real9" + secrets.token_hex(8)


def _node_type(rs, cluster_type: str = "single-node") -> str:
    """Cheapest orderable node type for *cluster_type* in this account/region."""
    available: list[str] = []
    marker = None
    while True:
        kwargs: dict[str, Any] = {"MaxRecords": 100}
        if marker:
            kwargs["Marker"] = marker
        resp = rs.describe_orderable_cluster_options(**kwargs)
        for opt in resp.get("OrderableClusterOptions", []):
            if opt.get("ClusterType") != cluster_type:
                continue
            nt = opt.get("NodeType")
            if nt and nt not in available:
                available.append(nt)
        marker = resp.get("Marker")
        if not marker:
            break
    chosen = next((nt for nt in NODE_TYPE_PREFERENCE if nt in available), None)
    if chosen is None:
        if not available:
            raise AssertionError(f"no orderable {cluster_type} options in this account/region")
        chosen = sorted(available)[0]
    return chosen


def _create_available_cluster(ctx) -> dict[str, Any]:
    redshift = ctx.client("redshift")
    sts = ctx.client("sts")
    cluster_id = ctx.unique_name("sim2real-rs-")
    subnet_group = _network_redshift_subnet_group(ctx, redshift)
    redshift.create_cluster(
        ClusterIdentifier=cluster_id,
        NodeType=_node_type(redshift),
        ClusterType="single-node",
        MasterUsername="adminuser",
        MasterUserPassword=_password(),
        DBName="dev",
        PubliclyAccessible=False,
        Tags=[{"Key": "sim2real-behavioral", "Value": "true"}],
        ClusterSubnetGroupName=subnet_group,
    )
    ctx.on_cleanup(
        lambda: redshift.delete_cluster(ClusterIdentifier=cluster_id, SkipFinalClusterSnapshot=True)
    )

    deadline = time.monotonic() + 900.0
    status = None
    cluster_info = None
    while time.monotonic() < deadline:
        cluster_info = redshift.describe_clusters(ClusterIdentifier=cluster_id)["Clusters"][0]
        status = cluster_info["ClusterStatus"]
        if status == "available":
            break
        time.sleep(2)
    if status != "available":
        raise AssertionError(f"cluster {cluster_id} never reached 'available' (last status={status})")

    # PutResourcePolicy/GetResourcePolicy address the cluster's NAMESPACE, not the cluster arn a
    # hand-built "arn:...:cluster:<id>" would produce (real AWS confirms this: GetResourcePolicy
    # against a hand-built cluster arn answers InvalidParameterValue, never ResourceNotFoundFault).
    namespace_arn = cluster_info["ClusterNamespaceArn"]
    identity = sts.get_caller_identity()
    partition = identity["Arn"].split(":")[1]
    return {"id": cluster_id, "arn": namespace_arn, "account": identity["Account"], "partition": partition}


def _network_redshift_subnet_group(ctx, client) -> str:
    """A Redshift cluster subnet group over the run's shared network, deleted once nothing uses it."""
    name = ctx.unique_name("sim2real-net-rsg-")
    client.create_cluster_subnet_group(
        ClusterSubnetGroupName=name,
        Description="sim2real shared network",
        SubnetIds=ctx.network().subnet_ids,
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )
    ctx.on_cleanup(
        lambda: _delete_when_released(
            lambda: client.delete_cluster_subnet_group(ClusterSubnetGroupName=name),
            ("InvalidClusterSubnetGroupStateFault", "ClusterSubnetGroupInUse"),
            ("ClusterSubnetGroupNotFoundFault",),
        )
    )
    return name


def _delete_when_released(delete, busy_codes, gone_codes, timeout_s=1500.0, interval_s=15.0):
    """Delete a subnet group, retrying while a resource that is being deleted still uses it."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            delete()
            return
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code in gone_codes:
                return
            if code not in busy_codes or time.monotonic() >= deadline:
                raise
        time.sleep(interval_s)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
