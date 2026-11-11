"""configuration-update-revision-increment."""
from __future__ import annotations

from behavioral_harness import tags


CHECK = "configuration-update-revision-increment"
GROUP = 'configuration'
SERVICES = ['kafka']

@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateConfiguration increments LatestRevision and both revisions remain readable."""
    msk = ctx.client("kafka")
    name = ctx.unique_name("sim2real-behav-config-upd-")
    resp = msk.create_configuration(
        Name=name,
        ServerProperties=b"num.partitions=1\n",
        KafkaVersions=["3.6.0"],
    )
    arn = resp["Arn"]
    ctx.on_cleanup(lambda _a=arn: msk.delete_configuration(Arn=_a))
    assert resp["LatestRevision"]["Revision"] == 1, (
        f"expected CreateConfiguration to mint revision 1, got {resp['LatestRevision']}"
    )

    updated = msk.update_configuration(
        Arn=arn, ServerProperties=b"num.partitions=3\n"
    )
    assert updated["LatestRevision"]["Revision"] == 2, (
        f"expected UpdateConfiguration to mint revision 2, got {updated['LatestRevision']}"
    )

    rev1 = msk.describe_configuration_revision(Arn=arn, Revision=1)
    rev2 = msk.describe_configuration_revision(Arn=arn, Revision=2)
    assert rev1["Revision"] == 1, f"revision 1 read back as {rev1['Revision']}"
    assert rev2["Revision"] == 2, f"revision 2 read back as {rev2['Revision']}"
    assert rev1["ServerProperties"] == b"num.partitions=1\n", (
        f"revision 1 must keep its original bytes, got {rev1['ServerProperties']!r}"
    )
    assert rev2["ServerProperties"] == b"num.partitions=3\n", (
        f"revision 2 must carry the updated bytes, got {rev2['ServerProperties']!r}"
    )

    revisions = msk.list_configuration_revisions(Arn=arn)["Revisions"]
    seen = {r["Revision"] for r in revisions}
    assert {1, 2} <= seen, f"expected revisions 1 and 2, got {seen}"

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
