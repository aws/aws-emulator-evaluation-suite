"""delete-nonexistent-analysis-report-id-rejected."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from behavioral_harness import tags

CHECK = "delete-nonexistent-analysis-report-id-rejected"
GROUP = "overly-permissive"
SERVICES = ["pi"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeletePerformanceAnalysisReport answers a well-formed never-issued AnalysisReportId with
    NotAuthorizedException "The specified resource is not authorized for this account", a real report
    id deletes, and ListPerformanceAnalysisReports afterwards does not list the never-issued id."""
    dbi = _create_pi_source(ctx)
    pi = ctx.client("pi")

    # positive control: DeletePerformanceAnalysisReport itself works, on a real id, for this
    # Identifier -- otherwise "rejects the never-issued id" is indistinguishable from "rejects
    # every DeletePerformanceAnalysisReport call".
    now = datetime.now(timezone.utc)
    real_report_id = pi.create_performance_analysis_report(
        ServiceType="RDS",
        Identifier=dbi,
        StartTime=now - timedelta(minutes=20),
        EndTime=now - timedelta(minutes=5),
    )["AnalysisReportId"]
    def _cleanup_real_report() -> None:
        from botocore.exceptions import ClientError

        try:
            pi.delete_performance_analysis_report(
                ServiceType="RDS", Identifier=dbi, AnalysisReportId=real_report_id
            )
        except ClientError as err:
            # PI answers a deleted or unknown report id with NotAuthorizedException.
            if err.response["Error"]["Code"] not in ("NotAuthorizedException", "ResourceNotFoundException"):
                raise

    ctx.on_cleanup(_cleanup_real_report)
    pi.delete_performance_analysis_report(
        ServiceType="RDS", Identifier=dbi, AnalysisReportId=real_report_id
    )

    bogus_report_id = "report-00000000000000000"  # matches ^report-[0-9a-f]{17}$, never issued

    error = _error(
        lambda: pi.delete_performance_analysis_report(
            ServiceType="RDS", Identifier=dbi, AnalysisReportId=bogus_report_id
        )
    )
    code, message = error.get("Code"), error.get("Message")
    assert code == "NotAuthorizedException", (
        f"expected a well-formed but never-issued AnalysisReportId to be rejected with "
        f"NotAuthorizedException (empirically PI's actual contract for this boundary -- it "
        f"does not disclose non-existence via InvalidArgumentException), got {code!r}"
    )
    assert message == "The specified resource is not authorized for this account", (
        f"expected the exact never-issued report id message, got {message!r}"
    )

    # positive control: the report subsystem for this Identifier still works (no side effect)
    listed = pi.list_performance_analysis_reports(ServiceType="RDS", Identifier=dbi)
    assert isinstance(listed["AnalysisReports"], list), (
        f"expected ListPerformanceAnalysisReports to keep working after the rejected delete, "
        f"got {listed!r}"
    )
    reported_ids = {s["AnalysisReportId"] for s in listed["AnalysisReports"]}
    assert bogus_report_id not in reported_ids, (
        f"the never-issued {bogus_report_id!r} must not appear in the report list, "
        f"got {reported_ids!r}"
    )


# ===== helpers =====
def _create_pi_source(ctx) -> str:
    """Create a PI-enabled RDS instance (Database Insights advanced mode, which the report ops
    require) owned by this check in the run's shared network, wait for it to be available, and
    delete it and its subnet group at cleanup."""
    import time

    from botocore.exceptions import ClientError

    rds = ctx.client("rds")
    db_id = ctx.unique_name("sim2real-pi-")
    subnet_group = f"{db_id}-subnets"

    def _teardown() -> None:
        # One deadline inside the suite's 900 s cleanup budget covers the delete retries and the wait.
        deadline = time.monotonic() + 880
        while True:
            try:
                rds.delete_db_instance(
                    DBInstanceIdentifier=db_id, SkipFinalSnapshot=True, DeleteAutomatedBackups=True
                )
                break
            except ClientError as err:
                code = err.response["Error"]["Code"]
                if code == "DBInstanceNotFound":
                    break
                if code != "InvalidDBInstanceState" or time.monotonic() >= deadline:
                    raise
                found = rds.describe_db_instances(
                    Filters=[{"Name": "db-instance-id", "Values": [db_id]}]
                )["DBInstances"]
                if not found or found[0]["DBInstanceStatus"] == "deleting":
                    break
            time.sleep(2)
        attempts = max(1, int((deadline - time.monotonic()) // 2))
        rds.get_waiter("db_instance_deleted").wait(
            DBInstanceIdentifier=db_id, WaiterConfig={"Delay": 2, "MaxAttempts": attempts}
        )
        try:
            rds.delete_db_subnet_group(DBSubnetGroupName=subnet_group)
        except ClientError as err:
            if err.response["Error"]["Code"] != "DBSubnetGroupNotFoundFault":
                raise

    ctx.on_cleanup(_teardown)
    rds.create_db_subnet_group(
        DBSubnetGroupName=subnet_group,
        DBSubnetGroupDescription="sim2real pi check",
        SubnetIds=ctx.network().subnet_ids,
        Tags=[{"Key": "Name", "Value": db_id}],
    )
    rds.create_db_instance(
        DBInstanceIdentifier=db_id,
        DBInstanceClass="db.t3.medium",
        Engine="mysql",
        MasterUsername="piadmin",
        MasterUserPassword="Sim2Real-Pw-12345",
        AllocatedStorage=20,
        EnablePerformanceInsights=True,
        DatabaseInsightsMode="advanced",
        PerformanceInsightsRetentionPeriod=465,
        BackupRetentionPeriod=0,
        PubliclyAccessible=False,
        MultiAZ=False,
        StorageType="gp2",
        DBSubnetGroupName=subnet_group,
        Tags=[{"Key": "Name", "Value": db_id}],
    )
    waiter = rds.get_waiter("db_instance_available")
    waiter.wait(DBInstanceIdentifier=db_id, WaiterConfig={"Delay": 2, "MaxAttempts": 900})
    desc = rds.describe_db_instances(DBInstanceIdentifier=db_id)["DBInstances"][0]
    assert desc.get("DatabaseInsightsMode") == "advanced", (
        f"expected Database Insights advanced mode on {db_id}, got {desc.get('DatabaseInsightsMode')!r}"
    )
    return desc["DbiResourceId"]


def _error(fn):
    """Call fn(); return its botocore Error dict. An unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response.get("Error", {})
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
