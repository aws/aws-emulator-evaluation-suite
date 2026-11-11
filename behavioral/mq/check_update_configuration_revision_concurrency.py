"""update-configuration-revision-concurrency."""
from __future__ import annotations

import base64
from concurrent.futures import ThreadPoolExecutor, as_completed

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-configuration-revision-concurrency"
GROUP = "concurrency"
SERVICES = ["mq"]

_RACERS = 8


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Concurrent UpdateConfiguration calls each get a unique revision, losers fail with
    ConflictException and its exact message, and the latest revision and the revision list account
    for exactly the successful calls.
    """
    mq = ctx.client("mq")
    name = ctx.unique_name("sim2real-mqcfg-")
    config_id = mq.create_configuration(
        EngineType="ACTIVEMQ",
        Name=name,
        Tags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-mqcfg"},
    )["Id"]
    ctx.on_cleanup(lambda: mq.delete_configuration(ConfigurationId=config_id))

    def _racer(i: int):
        xml = f'<broker xmlns="http://activemq.apache.org/schema/core"><!-- racer-{i} --></broker>'
        data_b64 = base64.b64encode(xml.encode("utf-8")).decode("ascii")
        try:
            resp = mq.update_configuration(ConfigurationId=config_id, Data=data_b64)
            return ("ok", resp["LatestRevision"]["Revision"])
        except ClientError as e:
            return ("err", (e.response["Error"]["Code"], e.response["Error"]["Message"]))

    results = []
    with ThreadPoolExecutor(max_workers=_RACERS) as pool:
        futures = [pool.submit(_racer, i) for i in range(_RACERS)]
        for fut in as_completed(futures):
            results.append(fut.result())

    successes = [r[1] for r in results if r[0] == "ok"]
    failures = [r[1] for r in results if r[0] == "err"]

    assert len(successes) >= 1, "expected at least one racer to succeed"
    # No two successful writers were assigned the same revision number.
    assert len(successes) == len(set(successes)), f"duplicate revisions assigned: {successes}"
    # Any losers must lose with the documented conflict error, not something else.
    conflict = f"Concurrent update to Configuration [{config_id}]. Retry to create a new revision."
    for code, message in failures:
        assert code == "ConflictException", code
        assert message == conflict, message

    final_revision = mq.describe_configuration(ConfigurationId=config_id)["LatestRevision"]["Revision"]
    assert final_revision == 1 + len(successes), (final_revision, successes)

    revisions_listed = {r["Revision"] for r in mq.list_configuration_revisions(ConfigurationId=config_id)["Revisions"]}
    assert revisions_listed == set(successes) | {1}, (revisions_listed, successes)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
