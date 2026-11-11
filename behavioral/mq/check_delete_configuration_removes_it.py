"""delete-configuration-removes-it."""
from __future__ import annotations

import base64

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-configuration-removes-it"
GROUP = "state"
SERVICES = ["mq"]


def _error(fn):
    """Call fn(); return its botocore (code, message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, call succeeded with {result!r}")


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeleteConfiguration removes the configuration; subsequent Describe returns NotFoundException,
    and a mutation against the dead id fails the same way."""
    mq = ctx.client("mq")
    name = ctx.unique_name("sim2real-mqcfg-")
    created = mq.create_configuration(EngineType="ACTIVEMQ", Name=name)
    config_id = created["Id"]

    # sanity: it exists before delete
    described_before = mq.describe_configuration(ConfigurationId=config_id)["Id"]
    assert described_before == config_id, f"expected DescribeConfiguration to echo {config_id}, got {described_before}"

    mq.delete_configuration(ConfigurationId=config_id)

    code, message = _error(lambda: mq.describe_configuration(ConfigurationId=config_id))
    assert code == "NotFoundException", f"expected DescribeConfiguration on a deleted id to return NotFoundException, got {code}"
    assert message == f"Configuration ID [{config_id}] can't be found. Make sure it exists.", message

    names_in_list = [c["Name"] for c in mq.list_configurations()["Configurations"]]
    assert name not in names_in_list, f"deleted configuration {name!r} still appears in ListConfigurations: {names_in_list}"

    xml = '<broker xmlns="http://activemq.apache.org/schema/core"><plugins/></broker>'
    data_b64 = base64.b64encode(xml.encode("utf-8")).decode("ascii")
    update_code, update_message = _error(lambda: mq.update_configuration(ConfigurationId=config_id, Data=data_b64))
    # UpdateConfiguration diverges from DescribeConfiguration on a deleted id: it does not treat the
    # id as not-found, it refuses the mutation as a conflict with the configuration's deleted state.
    assert update_code == "ConflictException", (
        f"expected UpdateConfiguration against a deleted id to return ConflictException, got {update_code}"
    )
    assert update_message == f"Concurrent update to Configuration [{config_id}]. Retry to create a new revision.", (
        update_message
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
