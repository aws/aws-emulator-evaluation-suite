"""resource-policy-put-get-delete-round-trip."""
from __future__ import annotations

import json
import secrets
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "resource-policy-put-get-delete-round-trip"
GROUP = "error-semantics"
SERVICES = ["redshift"]

UNSUPPORTED_TYPE = (
    "Resource type cluster isn't supported for the resource policy. Choose another resource type."
)


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Put/Get/DeleteResourcePolicy reject an available provisioned-cluster ARN with
    InvalidParameterValue and the exact unsupported-type message, while Put and Get round-trip a
    policy on a redshift-serverless namespace."""
    redshift = ctx.client("redshift")
    serverless = ctx.client("redshift-serverless")
    cluster = _create_available_cluster(ctx)

    clusters = redshift.describe_clusters(ClusterIdentifier=cluster["id"])["Clusters"]
    status = clusters[0]["ClusterStatus"]
    assert status == "available", (
        f"expected cluster {cluster['id']!r} status 'available' going into the probe, got {status!r}"
    )

    # Positive control: the same three operations succeed against a resource type the API does
    # support (a redshift-serverless namespace), in this same account/region/run.
    ns_name = ctx.unique_name("sim2real-rs-ns-")
    ns_arn = serverless.create_namespace(namespaceName=ns_name)["namespace"]["namespaceArn"]
    ctx.on_cleanup(lambda: serverless.delete_namespace(namespaceName=ns_name))

    control_policy = _integration_policy(cluster["account"], cluster["partition"], ns_arn)
    control_put = redshift.put_resource_policy(ResourceArn=ns_arn, Policy=json.dumps(control_policy))
    control_action = json.loads(control_put["ResourcePolicy"]["Policy"])["Statement"][0]["Action"]
    assert control_action == "redshift:CreateInboundIntegration", (
        "positive control: expected PutResourcePolicy against a namespace to echo action "
        f"redshift:CreateInboundIntegration, got {control_action!r}"
    )

    control_get = redshift.get_resource_policy(ResourceArn=ns_arn)
    control_principal = json.loads(control_get["ResourcePolicy"]["Policy"])["Statement"][0]["Principal"]["AWS"]
    expected_principal = control_policy["Statement"][0]["Principal"]["AWS"]
    assert control_principal == expected_principal, (
        f"positive control: expected fetched namespace policy Principal.AWS {expected_principal!r}, "
        f"got {control_principal!r}"
    )

    # Under test: the identical operation against a real, available cluster ARN is rejected outright.
    cluster_policy = json.dumps(_integration_policy(cluster["account"], cluster["partition"], cluster["arn"]))

    put_code, put_message = _error_code_and_message(
        lambda: redshift.put_resource_policy(ResourceArn=cluster["arn"], Policy=cluster_policy)
    )
    assert put_code == "InvalidParameterValue", (
        "expected PutResourcePolicy against a cluster ARN to fail with InvalidParameterValue, got "
        f"{put_code!r} ({put_message!r})"
    )
    assert put_message == UNSUPPORTED_TYPE, (
        f"expected PutResourcePolicy message {UNSUPPORTED_TYPE!r}, got {put_message!r}"
    )

    # Effect-absent: nothing was created, so an independent read reports the identical resource-type
    # rejection -- not ResourceNotFoundFault, which would mean the resource type is attachable but empty.
    get_code, get_message = _error_code_and_message(lambda: redshift.get_resource_policy(ResourceArn=cluster["arn"]))
    assert get_code == "InvalidParameterValue", (
        "expected GetResourcePolicy against a cluster ARN to fail with InvalidParameterValue (not "
        f"ResourceNotFoundFault, which would mean the resource type is attachable but empty), got "
        f"{get_code!r} ({get_message!r})"
    )
    assert get_message == UNSUPPORTED_TYPE, (
        f"expected GetResourcePolicy message {UNSUPPORTED_TYPE!r}, got {get_message!r}"
    )

    delete_code, delete_message = _error_code_and_message(
        lambda: redshift.delete_resource_policy(ResourceArn=cluster["arn"])
    )
    assert delete_code == "InvalidParameterValue", (
        "expected DeleteResourcePolicy against a cluster ARN to fail with InvalidParameterValue, got "
        f"{delete_code!r} ({delete_message!r})"
    )
    assert delete_message == UNSUPPORTED_TYPE, (
        f"expected DeleteResourcePolicy message {UNSUPPORTED_TYPE!r}, got {delete_message!r}"
    )


def _integration_policy(account: str, partition: str, resource_arn: str) -> dict[str, Any]:
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowSelfAccountInboundIntegration",
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:{partition}:iam::{account}:root"},
                "Action": "redshift:CreateInboundIntegration",
                "Resource": resource_arn,
            }
        ],
    }


def _error_code_and_message(fn) -> tuple[str, str | None]:
    """Call fn(); return (code, message) of the ClientError it raises. An unexpected SUCCESS
    raises, so a target that accepts a call real AWS refuses never reads as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        error = exc.response["Error"]
        return error["Code"], error.get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


def _password() -> str:
    # Satisfies the Redshift admin password constraints: 8-64 chars, at least one upper,
    # one lower, one digit, no '/', '"', '@', space or backslash.
    return "Sim2Real9" + secrets.token_hex(8)


def _create_available_cluster(ctx, node_type: str = "ra3.xlplus") -> dict[str, Any]:
    redshift = ctx.client("redshift")
    sts = ctx.client("sts")
    cluster_id = ctx.unique_name("sim2real-rs-")
    subnet_group = _network_redshift_subnet_group(ctx, redshift)
    redshift.create_cluster(
        ClusterIdentifier=cluster_id,
        NodeType=node_type,
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
    while time.monotonic() < deadline:
        clusters = redshift.describe_clusters(ClusterIdentifier=cluster_id)["Clusters"]
        status = clusters[0]["ClusterStatus"]
        if status == "available":
            break
        time.sleep(2)
    if status != "available":
        raise AssertionError(f"cluster {cluster_id} never reached 'available' (last status={status})")

    identity = sts.get_caller_identity()
    partition = identity["Arn"].split(":")[1]
    arn = f"arn:{partition}:redshift:{ctx.region}:{identity['Account']}:cluster:{cluster_id}"
    return {"id": cluster_id, "arn": arn, "account": identity["Account"], "partition": partition}


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
