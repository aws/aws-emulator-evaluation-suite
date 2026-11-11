"""replicator-read-paths-report-clean-miss."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "replicator-read-paths-report-clean-miss"
GROUP = 'read-paths'
SERVICES = ['kafka']

def _err(fn):
    """Call fn(); return (Error.Code, Error.Message) of the ClientError it raises. An unexpected
    SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


def _account_id(ctx):
    if not hasattr(ctx, "_kafka_account_id"):
        ctx._kafka_account_id = ctx.client("sts").get_caller_identity()["Account"]
    return ctx._kafka_account_id


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Describe/Delete of a nonexistent replicator -> NotFoundException; name filter is exact."""
    msk = ctx.client("kafka")
    name = ctx.unique_name("sim2real-behav-nonexistent-repl-")
    bogus = f"arn:aws:kafka:{ctx.region}:{_account_id(ctx)}:replicator/{name}/00000000-0000-0000-0000-000000000000-1"

    # Positive control: the replicator API surface is reachable and returns its
    # normal shape, so the not-found assertions below cannot be satisfied merely
    # by an unimplemented/always-erroring replicator API.
    listed_all = msk.list_replicators()
    assert "Replicators" in listed_all, f"list_replicators positive control: unexpected shape {listed_all!r}"

    expected = (
        "NotFoundException",
        "Invalid parameter replicatorArn: The requested resource doesn\u2019t exist.",
    )
    describe_err = _err(lambda: msk.describe_replicator(ReplicatorArn=bogus))
    assert describe_err == expected, f"describe: expected {expected!r}, got {describe_err!r}"

    delete_err = _err(lambda: msk.delete_replicator(ReplicatorArn=bogus))
    assert delete_err == expected, f"delete: expected {expected!r}, got {delete_err!r}"

    listed = msk.list_replicators(ReplicatorNameFilter=name)["Replicators"]
    assert listed == [], f"expected no replicators matching exact-name filter {name!r}, got {listed}"

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
