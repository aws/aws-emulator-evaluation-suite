"""data-source-introspection-not-found."""
from __future__ import annotations

import uuid

from behavioral_harness import tags

CHECK = "data-source-introspection-not-found"
GROUP = "error-semantics"
SERVICES = ["appsync"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetDataSourceIntrospection answers a real job id and fails NotFoundException for an unknown
    introspectionId."""
    appsync = ctx.client("appsync")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    region = ctx.region

    resource_arn = (
        f"arn:aws:rds:{region}:{account_id}:cluster:"
        f"{ctx.unique_name('sim2real-appsync-nf-cluster-')}"
    )
    secret_arn = (
        f"arn:aws:secretsmanager:{region}:{account_id}:secret:"
        f"{ctx.unique_name('sim2real-appsync-nf-secret-')}"
    )
    started = appsync.start_data_source_introspection(
        rdsDataApiConfig={
            "resourceArn": resource_arn,
            "secretArn": secret_arn,
            "databaseName": "sim2real_nf_db",
        }
    )
    real_id = started["introspectionId"]

    real = appsync.get_data_source_introspection(introspectionId=real_id)
    assert real["introspectionId"] == real_id, (
        f"expected a just-started introspectionId to read back as itself, got {real!r}"
    )

    bogus_id = str(uuid.uuid4())
    error = _error(
        lambda: appsync.get_data_source_introspection(introspectionId=bogus_id)
    )
    expected = ("NotFoundException", "No introspection was found that matches the supplied ID.")
    assert error == expected, (
        f"expected {expected} for unknown introspectionId, got {error!r}"
    )


def _error(fn):
    """Call fn(); return its (error code, message). An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"].get("Code"), err.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
