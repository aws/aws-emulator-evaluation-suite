"""client-vpc-connection-state-transition."""
from __future__ import annotations

import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "client-vpc-connection-state-transition"
GROUP = 'overly-permissive'
SERVICES = ['kafka']


def _err(fn):
    """Call fn(); return the botocore Error.Code if a ClientError is raised. An unexpected SUCCESS
    raises, because a target that accepts a call real AWS rejects is the strongest signal available."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {}).get("Code")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _account_id(ctx):
    if not hasattr(ctx, "_kafka_account_id"):
        ctx._kafka_account_id = ctx.client("sts").get_caller_identity()["Account"]
    return ctx._kafka_account_id


def _bogus_cluster_arn(ctx):
    name = ctx.unique_name("sim2real-behav-ghost-cluster-")
    return f"arn:aws:kafka:{ctx.region}:{_account_id(ctx)}:cluster/{name}/{uuid.uuid4()}-2"


def _bogus_vpc_connection_arn(ctx):
    acct = _account_id(ctx)
    name = ctx.unique_name("sim2real-behav-ghost-vpc-")
    return f"arn:aws:kafka:{ctx.region}:{acct}:vpc-connection/{acct}/{name}/{uuid.uuid4()}-7"


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ListClientVpcConnections and RejectClientVpcConnection for a cluster that does not exist both fail
    with NotFoundException rather than inventing a connection list or a REJECTED transition."""
    msk = ctx.client("kafka")

    # Positive control: the kafka API and these credentials are generally healthy, so the
    # NotFoundExceptions asserted below are specific to the bogus ARNs under test rather than a
    # blanket outage that would make every call fail the same way.
    listed = msk.list_vpc_connections()
    assert "VpcConnections" in listed, f"listed={listed!r}"

    ghost = _bogus_cluster_arn(ctx)
    unassociated = _bogus_vpc_connection_arn(ctx)

    observed = {
        "ListClientVpcConnections": _err(
            lambda: msk.list_client_vpc_connections(ClusterArn=ghost)
        ),
        "RejectClientVpcConnection": _err(
            lambda: msk.reject_client_vpc_connection(
                ClusterArn=ghost, VpcConnectionArn=unassociated
            )
        ),
    }
    expected = {
        "ListClientVpcConnections": "NotFoundException",
        "RejectClientVpcConnection": "NotFoundException",
    }
    assert observed == expected, f"observed={observed}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
