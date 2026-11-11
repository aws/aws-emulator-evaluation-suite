"""lakehouse-configuration-idc-application-not-exists-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "lakehouse-configuration-idc-application-not-exists-rejected"
GROUP = "error-semantics"
SERVICES = ["redshift"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ModifyLakehouseConfiguration with an ARN naming no RedshiftIdcApplication is rejected with
    RedshiftIdcApplicationNotExists and its exact message, the lakehouse status is unchanged, and a
    dry run on the same cluster answers DryRunOperation."""
    redshift = ctx.client("redshift")
    account_id = ctx.client("sts").get_caller_identity()["Account"]

    cluster_id = ctx.unique_name("sim2real-lakehouse-").lower()
    subnet_group = _network_redshift_subnet_group(ctx, redshift)
    redshift.create_cluster(
        ClusterIdentifier=cluster_id,
        # RA3, not DC2: CreateCluster(NodeType="dc2.large") is rejected outright
        # (InvalidParameterValue: Invalid node type) although the Smithy model documents
        # it, and lakehouse configuration itself requires RA3 storage.
        NodeType="ra3.large",
        MasterUsername="sim2realadmin",
        MasterUserPassword="Sim2RealTest1234!",
        ClusterType="single-node",
        DBName="dev",
        PubliclyAccessible=False,
        Tags=[{"Key": "sim2real-behavioral", "Value": "true"}],
        ClusterSubnetGroupName=subnet_group,
    )
    ctx.on_cleanup(lambda: _delete_cluster(redshift, cluster_id))
    _wait_for_status(ctx, redshift, cluster_id, "available", timeout_s=900)
    _wait_for_availability(redshift, cluster_id, timeout_s=300)

    # Precondition: LakehouseIdcRegistration="Associate" only
    # validates the IdC application ARN once the cluster already has Redshift federated
    # permissions (a Glue catalog) registered. On a plain, never-registered cluster the call
    # fails closed with InvalidClusterState before it ever reaches ARN validation -- it does
    # NOT surface RedshiftIdcApplicationNotExists. Register first, matching that real order.
    _retry_on_invalid_cluster_state(
        lambda: redshift.modify_lakehouse_configuration(
            ClusterIdentifier=cluster_id,
            LakehouseRegistration="Register",
            CatalogName=cluster_id,
        ),
        timeout_s=180,
    )
    _wait_for_status(ctx, redshift, cluster_id, "available", timeout_s=300)
    _wait_for_availability(redshift, cluster_id, timeout_s=180)

    baseline = redshift.describe_clusters(ClusterIdentifier=cluster_id)["Clusters"][0]
    baseline_status = baseline.get("LakehouseRegistrationStatus")

    bogus_idc_app_arn = (
        f"arn:aws:redshift:{ctx.region}:{account_id}:redshiftidcapplication:"
        f"{ctx.unique_name('sim2real-nope-')}"
    )
    code, message = _error_retrying_invalid_state(
        lambda: redshift.modify_lakehouse_configuration(
            ClusterIdentifier=cluster_id,
            LakehouseIdcRegistration="Associate",
            LakehouseIdcApplicationArn=bogus_idc_app_arn,
        ),
        timeout_s=180,
    )
    assert code == "RedshiftIdcApplicationNotExists", code
    assert message == (
        f"The RedshiftIdcApplication with the ARN {bogus_idc_app_arn} wasn't found, "
        "or the status isn't Completed."
    ), f"unexpected RedshiftIdcApplicationNotExists message {message!r}"

    # effect absent: the failed Associate left the (now Register-ed) cluster's lakehouse
    # state exactly as Register left it -- an independent read shows no partial association.
    after = redshift.describe_clusters(ClusterIdentifier=cluster_id)["Clusters"][0]
    after_status = after.get("LakehouseRegistrationStatus")
    assert after_status == baseline_status, (
        f"expected LakehouseRegistrationStatus to stay {baseline_status!r}, got {after_status!r}"
    )

    # positive control: a benign, no-arn toggle on the same cluster still succeeds, proving
    # the rejection above is specific to the bogus ARN and not a blanket denial. A
    # successful DryRun does not return 200 -- it raises the EC2-style
    # DryRunOperation error ("Request would have succeeded, but DryRun flag is set"), which
    # is itself the positive signal, not a rejection.
    dry_run_code, dry_run_message = _error_retrying_invalid_state(
        lambda: redshift.modify_lakehouse_configuration(
            ClusterIdentifier=cluster_id, DryRun=True, LakehouseRegistration="Register"
        ),
        timeout_s=60,
    )
    assert dry_run_code == "DryRunOperation", (
        f"expected the dry run to report it would succeed, got {dry_run_code}"
    )
    assert dry_run_message == "Request would have succeeded, but DryRun flag is set.", (
        f"unexpected DryRunOperation message {dry_run_message!r}"
    )


def _error_retrying_invalid_state(fn, timeout_s):
    """Call fn() until it stops answering InvalidClusterState; return (Error.Code, Error.Message).
    An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            result = fn()
        except ClientError as err:
            error = err.response.get("Error", {})
            code = error.get("Code")
            if code == "InvalidClusterState" and time.monotonic() < deadline:
                time.sleep(2)
                continue
            return code, error.get("Message")
        raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")


def _retry_on_invalid_cluster_state(fn, timeout_s):
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return fn()
        except ClientError as err:
            if err.response["Error"]["Code"] != "InvalidClusterState" or time.monotonic() >= deadline:
                raise
            time.sleep(2)


def _wait_for_status(ctx, redshift, cluster_id, target_status, timeout_s):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = redshift.describe_clusters(ClusterIdentifier=cluster_id)["Clusters"][0]
        if last["ClusterStatus"] == target_status:
            return last
        time.sleep(2)
    raise AssertionError(f"cluster never reached {target_status!r} (last seen: {last})")


def _wait_for_availability(redshift, cluster_id, timeout_s):
    """ClusterStatus can already read 'available' while ClusterAvailabilityStatus is still
    'Modifying', which otherwise causes a spurious InvalidClusterState on the next mutating
    call."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = redshift.describe_clusters(ClusterIdentifier=cluster_id)["Clusters"][0].get(
            "ClusterAvailabilityStatus"
        )
        if last == "Available":
            return
        time.sleep(2)
    raise AssertionError(f"cluster availability never reached 'Available' (last seen: {last!r})")


def _delete_cluster(redshift, cluster_id):
    """Delete the cluster. DeleteCluster refuses a cluster that still has a lakehouse Glue
    catalog registered, so deregister it first, then retry through InvalidClusterState while the
    deregistration runs."""
    from botocore.exceptions import ClientError

    deregistered = False
    deadline = time.monotonic() + 840
    while time.monotonic() < deadline:
        try:
            redshift.delete_cluster(ClusterIdentifier=cluster_id, SkipFinalClusterSnapshot=True)
            return
        except ClientError as err:
            code = err.response["Error"]["Code"]
            if code == "ClusterNotFound":
                return
            if code != "InvalidClusterState":
                raise
        if not deregistered:
            try:
                status = redshift.describe_clusters(ClusterIdentifier=cluster_id)["Clusters"][0].get(
                    "LakehouseRegistrationStatus"
                )
            except ClientError as err:
                if err.response["Error"]["Code"] == "ClusterNotFound":
                    return
                raise
            if status == "REGISTERED":
                try:
                    redshift.modify_lakehouse_configuration(
                        ClusterIdentifier=cluster_id, LakehouseRegistration="Deregister"
                    )
                    deregistered = True
                except ClientError as err:
                    if err.response["Error"]["Code"] != "InvalidClusterState":
                        raise
        time.sleep(15)
    raise AssertionError(f"could not delete cluster {cluster_id} within retry budget")


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
