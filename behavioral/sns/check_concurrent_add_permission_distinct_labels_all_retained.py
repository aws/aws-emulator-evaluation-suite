"""concurrent-add-permission-distinct-labels-all-retained."""
from __future__ import annotations

import json
from concurrent.futures import ThreadPoolExecutor

from behavioral_harness import tags

CHECK = "concurrent-add-permission-distinct-labels-all-retained"
GROUP = 'topic-policy'
SERVICES = ['sns']

_WRITERS = 8


@tags("axis:happy-path", "cap:c2", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Eight concurrent AddPermission calls with distinct labels all survive in the topic policy
    beside the default statement; an unlocked read-modify-write store loses some of them."""
    sns = ctx.client("sns")
    arn = sns.create_topic(Name=ctx.unique_name("sim2real-behav-sns-ccperm-"),
                           Tags=[{"Key": "sim2real", "Value": CHECK}])["TopicArn"]
    ctx.on_cleanup(lambda: sns.delete_topic(TopicArn=arn))
    account = arn.split(":")[4]
    base = {s.get("Sid") for s in json.loads(
        sns.get_topic_attributes(TopicArn=arn)["Attributes"]["Policy"])["Statement"]}

    labels = [f"{ctx.unique_name('sim2real-behav-lbl-')}-{i}" for i in range(_WRITERS)]
    with ThreadPoolExecutor(max_workers=_WRITERS) as pool:
        futures = [pool.submit(sns.add_permission, TopicArn=arn, Label=lb,
                               AWSAccountId=[account], ActionName=["Publish"]) for lb in labels]
        for f in futures:
            f.result()

    sids = {s.get("Sid") for s in json.loads(
        sns.get_topic_attributes(TopicArn=arn)["Attributes"]["Policy"])["Statement"]}
    missing = sorted(set(labels) - sids)
    assert not missing, f"{len(missing)} of {_WRITERS} concurrently added statements were lost"
    assert sids == base | set(labels), (
        f"the policy must hold the default statement(s) plus the {_WRITERS} labels, got {len(sids)} Sids"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
