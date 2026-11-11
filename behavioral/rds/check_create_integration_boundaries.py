"""create-integration-boundaries."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-integration-boundaries"
GROUP = 'integrations'
SERVICES = ['rds']

ERR_DB_CLUSTER_NOT_FOUND = "DBClusterNotFoundFault"


def _error_code(fn):
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(
        f"expected CreateIntegration to be rejected, but it SUCCEEDED and returned {result!r}"
    )


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateIntegration validates TargetArn syntax before looking up the source cluster.

    A nonexistent SourceArn fails DBClusterNotFoundFault; a malformed TargetArn with the same
    nonexistent source fails InvalidParameterValue.
    """
    rds = ctx.client("rds")
    account = ctx.client("sts").get_caller_identity()["Account"]
    bogus_cluster = ctx.unique_name("sim2real-behav-clu-missing-")
    source_arn = f"arn:aws:rds:{ctx.region}:{account}:cluster:{bogus_cluster}"
    target_arn = (
        f"arn:aws:redshift-serverless:{ctx.region}:{account}:"
        "namespace/00000000-0000-0000-0000-000000000000"
    )
    code, message = _error_code(
        lambda: rds.create_integration(
            IntegrationName=ctx.unique_name("sim2real-behav-zetl-"),
            SourceArn=source_arn,
            TargetArn=target_arn,
        )
    )
    assert code == ERR_DB_CLUSTER_NOT_FOUND, f"unexpected error code: {code}"
    expected = f"RDS DB cluster {bogus_cluster} does not exist"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    code2, message2 = _error_code(
        lambda: rds.create_integration(
            IntegrationName=ctx.unique_name("sim2real-behav-zetl-"),
            SourceArn=source_arn,
            TargetArn="not-a-valid-arn-but-long-enough",
        )
    )
    # Same nonexistent SourceArn, now paired with a malformed TargetArn. Real AWS answers
    # InvalidParameterValue, so ARN syntax is validated BEFORE the source lookup. Do NOT
    # accept DBClusterNotFoundFault here: it is what the equally-nonexistent source would
    # produce, so admitting it makes the probe vacuous (it would pass under either ordering)
    # and lets an emulator with the order reversed slip through.
    assert code2 == "InvalidParameterValue", (
        f"expected TargetArn syntax validation to precede the source lookup "
        f"(InvalidParameterValue, not {ERR_DB_CLUSTER_NOT_FOUND}), got {code2}"
    )
    expected2 = (
        "Amazon RDS can't create the zero-ETL integration because the target type isn't valid. "
        "Choose either an Amazon Redshift data warehouse or an AWS Glue Data Catalog with "
        "Redshift Managed Storage (RMS) as the target."
    )
    assert message2 == expected2, f"expected message {expected2!r}, got {message2!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
