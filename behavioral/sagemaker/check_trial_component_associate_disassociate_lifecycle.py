"""trial-component-associate-disassociate-lifecycle."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "trial-component-associate-disassociate-lifecycle"
GROUP = "state-machine"
SERVICES = ["sagemaker"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """AssociateTrialComponent links a standalone component to a trial (visible via
    ListTrialComponents(TrialName=...)) and DisassociateTrialComponent removes that link."""
    sm = ctx.client("sagemaker")
    experiment_name = ctx.unique_name("sim2real-sm-exp-")
    trial_name = ctx.unique_name("sim2real-sm-trial-")
    component_name = ctx.unique_name("sim2real-sm-tc-")

    resource_tags = [{"Key": "sim2real", "Value": CHECK}]

    ctx.on_cleanup(lambda: _safe(lambda: sm.delete_experiment(ExperimentName=experiment_name)))
    sm.create_experiment(ExperimentName=experiment_name, Tags=resource_tags)

    ctx.on_cleanup(lambda: _safe(lambda: sm.delete_trial(TrialName=trial_name)))
    sm.create_trial(TrialName=trial_name, ExperimentName=experiment_name, Tags=resource_tags)

    ctx.on_cleanup(lambda: _safe(lambda: sm.delete_trial_component(TrialComponentName=component_name)))
    sm.create_trial_component(TrialComponentName=component_name, Tags=resource_tags)

    def _list_names():
        resp = sm.list_trial_components(TrialName=trial_name)
        return {c["TrialComponentName"] for c in resp.get("TrialComponentSummaries", [])}

    before = _list_names()
    assert component_name not in before, (
        f"expected {component_name} absent from ListTrialComponents before association, got {before}"
    )

    sm.associate_trial_component(TrialComponentName=component_name, TrialName=trial_name)
    after_associate = _list_names()
    assert component_name in after_associate, (
        f"expected {component_name} present in ListTrialComponents after AssociateTrialComponent, "
        f"got {after_associate}"
    )

    sm.disassociate_trial_component(TrialComponentName=component_name, TrialName=trial_name)
    after_disassociate = _list_names()
    assert component_name not in after_disassociate, (
        f"expected {component_name} absent from ListTrialComponents after DisassociateTrialComponent, "
        f"got {after_disassociate}"
    )


def _safe(fn) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFound":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
