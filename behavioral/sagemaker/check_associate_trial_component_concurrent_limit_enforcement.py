"""associate-trial-component-concurrent-limit-enforcement."""
from __future__ import annotations

import threading
from concurrent.futures import ThreadPoolExecutor

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "associate-trial-component-concurrent-limit-enforcement"
GROUP = "concurrency"
SERVICES = ["sagemaker"]

_N = 5


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Concurrent AssociateTrialComponent calls for distinct components, plus racing duplicates of one
    pair, leave the trial with exactly one association per component and every response naming the
    trial's ARN."""
    sm = ctx.client("sagemaker")

    experiment_name = ctx.unique_name("sim2real-behav-exp-")
    sm.create_experiment(ExperimentName=experiment_name)
    ctx.on_cleanup(lambda: sm.delete_experiment(ExperimentName=experiment_name))

    trial_name = ctx.unique_name("sim2real-behav-trial-")
    trial_arn = sm.create_trial(TrialName=trial_name, ExperimentName=experiment_name)["TrialArn"]
    ctx.on_cleanup(lambda: sm.delete_trial(TrialName=trial_name))

    component_names = [ctx.unique_name(f"sim2real-behav-tc{i}-") for i in range(_N)]
    for name in component_names:
        sm.create_trial_component(TrialComponentName=name)
        ctx.on_cleanup(lambda n=name: sm.delete_trial_component(TrialComponentName=n))

    def _disassociate_all():
        for name in component_names:
            try:
                sm.disassociate_trial_component(TrialComponentName=name, TrialName=trial_name)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "ResourceNotFound":
                    raise

    ctx.on_cleanup(_disassociate_all)

    # N distinct associations, plus two extra racers duplicating component 0's association.
    jobs = list(component_names) + [component_names[0], component_names[0]]
    barrier = threading.Barrier(len(jobs))

    def _associate(name: str):
        barrier.wait()
        return sm.associate_trial_component(TrialComponentName=name, TrialName=trial_name)

    with ThreadPoolExecutor(max_workers=len(jobs)) as pool:
        results = [f.result() for f in [pool.submit(_associate, j) for j in jobs]]

    for r in results:
        assert r["TrialArn"] == trial_arn, f"unexpected TrialArn in response: {r}"

    associated: list[str] = []
    paginator = sm.get_paginator("list_trial_components")
    for page in paginator.paginate(TrialName=trial_name):
        for summary in page["TrialComponentSummaries"]:
            associated.append(summary["TrialComponentName"])

    # A set collapses a duplicated list entry, which is exactly the evidence an
    # over-admitted racer would leave behind -- so the raw count must be checked
    # before any deduplication happens.
    assert len(associated) == len(component_names), (
        f"expected exactly {len(component_names)} trial component associations, "
        f"got {len(associated)}: {associated} (duplicate racer inflated the final "
        "association count)"
    )
    assert set(associated) == set(component_names), (
        f"expected exactly {set(component_names)} associated, got {set(associated)} "
        "(wrong component ended up associated)"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
