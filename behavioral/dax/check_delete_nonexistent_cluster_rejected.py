"""delete-nonexistent-cluster-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-nonexistent-cluster-rejected"
GROUP = "error-semantics"
SERVICES = ["dax"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteCluster on a name that was never created is rejected with
    ClusterNotFoundFault, while deleting a resource that really exists (a parameter
    group, exercised as the positive control in the same file) succeeds normally."""
    dax = ctx.client("dax")
    bogus_name = ctx.unique_name("sim2real-dax-missing-")

    code, message = _expect_error(lambda: dax.delete_cluster(ClusterName=bogus_name))
    assert code == "ClusterNotFoundFault", f"unexpected code: {code!r}"
    assert message == "Cluster not found.", f"unexpected message: {message!r}"

    # Positive control: deleting a resource that actually exists succeeds and the
    # resource is confirmed gone afterwards.
    pg_name = ctx.unique_name("sim2real-dax-pg-")
    dax.create_parameter_group(ParameterGroupName=pg_name, Description="control")
    ctx.on_cleanup(lambda: _safe_delete_parameter_group(ctx, pg_name))
    dax.delete_parameter_group(ParameterGroupName=pg_name)
    gone_code, gone_message = _expect_error(lambda: dax.describe_parameter_groups(ParameterGroupNames=[pg_name]))
    assert gone_code == "ParameterGroupNotFoundFault", f"unexpected code: {gone_code!r}"
    assert gone_message == "Parameter Group not found.", f"unexpected message: {gone_message!r}"


def _expect_error(fn):
    """Call fn(); return its botocore (code, message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _safe_delete_parameter_group(ctx, name):
    try:
        ctx.client("dax").delete_parameter_group(ParameterGroupName=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "ParameterGroupNotFoundFault",
            "ServiceLinkedRoleNotFoundFault",
        ):
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
