"""configuration-revision-not-found."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "configuration-revision-not-found"
GROUP = 'overly-permissive'
SERVICES = ['kafka']

def _err(fn):
    """Call fn(); return (Error.Code, Error.Message) if a ClientError is raised. An unexpected
    SUCCESS raises."""
    try:
        resp = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {resp}")


_DEFAULT_KAFKA_VERSION = "3.9.x"
_PROVISIONED_INSTANCE_TYPE = "kafka.m5.large"


def _create_test_configuration(ctx, msk, name_prefix="config-",
                               server_properties=b"num.partitions=1\n", kafka_versions=None):
    """Create an MSK configuration; register teardown. Returns (arn, name)."""
    name = ctx.unique_name("sim2real-behav-" + name_prefix)
    resp = msk.create_configuration(
        Name=name,
        Description="behavioral test configuration",
        KafkaVersions=kafka_versions or [_DEFAULT_KAFKA_VERSION],
        ServerProperties=server_properties,
    )
    arn = resp["Arn"]
    ctx.on_cleanup(lambda: msk.delete_configuration(Arn=arn))
    return arn, name


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A fresh configuration lists only revision 1 and DescribeConfigurationRevision(1) returns its
    properties, while revision 99 fails with BadRequestException "Configuration ARN does not exist." rather
    than NotFoundException."""
    msk = ctx.client("kafka")
    server_properties = b"num.partitions=1\n"
    arn, _name = _create_test_configuration(
        ctx, msk, name_prefix="config-rev-", server_properties=server_properties)

    revisions = msk.list_configuration_revisions(Arn=arn)["Revisions"]
    assert [r["Revision"] for r in revisions] == [1], revisions

    rev1 = msk.describe_configuration_revision(Arn=arn, Revision=1)
    assert rev1["Revision"] == 1, rev1
    assert rev1["ServerProperties"] == server_properties, rev1

    code, message = _err(lambda: msk.describe_configuration_revision(Arn=arn, Revision=99))
    assert code == "BadRequestException", f"expected BadRequestException, got {code}"
    assert message == "Configuration ARN does not exist.", f"unexpected message: {message!r}"

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
