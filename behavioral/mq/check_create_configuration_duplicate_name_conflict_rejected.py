"""create-configuration-duplicate-name-conflict-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-configuration-duplicate-name-conflict-rejected"
GROUP = "overly-permissive"
SERVICES = ["mq"]


def _error(fn):
    """Call fn(); return its botocore (code, message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected a rejection but the call succeeded: {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateConfiguration on a nonexistent ConfigurationId is rejected with NotFoundException."""
    mq = ctx.client("mq")

    # positive control: duplicate Name is in fact allowed — configurations are
    # identified by Id, not Name. Two configs may share a Name with distinct Ids.
    name = ctx.unique_name("sim2real-mqcfg-")
    first = mq.create_configuration(EngineType="ACTIVEMQ", Name=name, Tags={"sim2real": CHECK})
    first_id = first["Id"]
    ctx.on_cleanup(lambda: mq.delete_configuration(ConfigurationId=first_id))

    second = mq.create_configuration(EngineType="ACTIVEMQ", Name=name, Tags={"sim2real": CHECK})
    second_id = second["Id"]
    ctx.on_cleanup(lambda: mq.delete_configuration(ConfigurationId=second_id))
    assert second_id != first_id, f"two CreateConfiguration calls with the same Name got the same Id: {first_id!r}"
    matches = [c for c in mq.list_configurations()["Configurations"] if c["Name"] == name]
    assert len(matches) == 2, matches

    # overly-permissive boundary: a syntactically valid but never-issued
    # ConfigurationId must be rejected, not treated as an implicit create/no-op.
    bogus_id = "c-00000000-0000-0000-0000-000000000000"
    code, message = _error(
        lambda: mq.update_configuration(ConfigurationId=bogus_id, Data="PGJyb2tlciBub3M9InRydWUiPjwvYnJva2VyPg==")
    )
    assert code == "NotFoundException", code
    expected = f"Configuration ID [{bogus_id}] could not be found. Check the ID and try again."
    assert message == expected, message

    # independent read, different operation than the rejected mutation: the bogus id must still not
    # exist.
    describe_code, describe_message = _error(lambda: mq.describe_configuration(ConfigurationId=bogus_id))
    assert describe_code == "NotFoundException", describe_code
    expected = f"Configuration ID [{bogus_id}] can't be found. Make sure it exists."
    assert describe_message == expected, describe_message


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
