"""get-data-source-introspection-invalid-id-not-found."""
from __future__ import annotations

import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-data-source-introspection-invalid-id-not-found"
GROUP = "error-semantics"
SERVICES = ["appsync"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetDataSourceIntrospection with an unknown introspectionId returns NotFoundException.

    A real job's id reads back first, so the error means this id is unknown, not that all ids fail.
    """
    appsync = ctx.client("appsync")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    region = ctx.region

    resource_arn = (
        f"arn:aws:rds:{region}:{account_id}:cluster:"
        f"{ctx.unique_name('sim2real-appsync-gdi-cluster-')}"
    )
    secret_arn = (
        f"arn:aws:secretsmanager:{region}:{account_id}:secret:"
        f"{ctx.unique_name('sim2real-appsync-gdi-secret-')}"
    )
    # A well-formed ARN for a nonexistent cluster is enough to start a job; no cluster is needed.
    started = appsync.start_data_source_introspection(
        rdsDataApiConfig={
            "resourceArn": resource_arn,
            "secretArn": secret_arn,
            "databaseName": "sim2real_gdi_db",
        }
    )
    real_id = started["introspectionId"]

    real = appsync.get_data_source_introspection(introspectionId=real_id)
    assert real["introspectionId"] == real_id, (
        f"expected the just-started introspectionId to read back, got {real!r}"
    )

    bogus_id = str(uuid.uuid4())
    code, message = _error(
        lambda: appsync.get_data_source_introspection(introspectionId=bogus_id)
    )
    assert code == "NotFoundException", f"expected NotFoundException, got {code!r}"
    assert message == "No introspection was found that matches the supplied ID.", (
        f"unexpected message: {message!r}"
    )


def _error(fn):
    """Call fn() and return its botocore error (code, message); a call that succeeds raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
