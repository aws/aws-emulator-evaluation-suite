"""vpcconnection-read-paths-report-clean-miss."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "vpcconnection-read-paths-report-clean-miss"
GROUP = 'read-paths'
SERVICES = ['kafka']

_BAD_REQUEST = ("BadRequestException", "One or more of the parameters are not valid.")

def _err(fn):
    """Call fn(); return the botocore (Error.Code, Error.Message) of the ClientError it raises.

    An unexpected success raises with the actual result rather than reading as a code mismatch.
    """
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _account_id(ctx):
    if not hasattr(ctx, "_kafka_account_id"):
        ctx._kafka_account_id = ctx.client("sts").get_caller_identity()["Account"]
    return ctx._kafka_account_id


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DescribeVpcConnection and DeleteVpcConnection on a nonexistent ARN fail with
    BadRequestException (replicators use NotFoundException); ListVpcConnections omits the ARN."""
    msk = ctx.client("kafka")
    bogus = (
        f"arn:aws:kafka:{ctx.region}:{_account_id(ctx)}:vpc-connection/"
        f"{ctx.unique_name('sim2real-behav-nonexistent-')}/00000000-0000-0000-0000-000000000000-1"
    )

    describe_code = _err(lambda: msk.describe_vpc_connection(Arn=bogus))
    assert describe_code == _BAD_REQUEST, f"describe: expected {_BAD_REQUEST!r}, got {describe_code!r}"

    delete_code = _err(lambda: msk.delete_vpc_connection(Arn=bogus))
    assert delete_code == _BAD_REQUEST, f"delete: expected {_BAD_REQUEST!r}, got {delete_code!r}"

    listed = msk.list_vpc_connections()["VpcConnections"]
    assert all(c["VpcConnectionArn"] != bogus for c in listed), listed

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
