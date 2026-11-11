"""trial-component-metric-numeric-precision-preserved."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "trial-component-metric-numeric-precision-preserved"
GROUP = "representation"
SERVICES = ["sagemaker"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A high-precision double value written as a TrialComponent numeric
    Parameter on CreateTrialComponent is returned unchanged -- bit-for-bit, no
    rounding or truncation -- by DescribeTrialComponent."""
    sm = ctx.client("sagemaker")

    precise_value = 3.14159265358979
    another_value = 2.718281828459045

    trial_component_name = ctx.unique_name("sim2real-tc-")
    sm.create_trial_component(
        TrialComponentName=trial_component_name,
        Parameters={
            "precise_metric": {"NumberValue": precise_value},
            "another_metric": {"NumberValue": another_value},
            "categorical_param": {"StringValue": "control-group"},
        },
        Tags=[{"Key": "sim2real:check", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _delete_trial_component(sm, trial_component_name))

    described = sm.describe_trial_component(TrialComponentName=trial_component_name)
    parameters = described["Parameters"]

    assert parameters["precise_metric"]["NumberValue"] == precise_value, (
        f"expected exact {precise_value!r}, got {parameters['precise_metric']['NumberValue']!r}"
    )
    assert parameters["another_metric"]["NumberValue"] == another_value, (
        f"expected exact {another_value!r}, got {parameters['another_metric']['NumberValue']!r}"
    )
    assert parameters["categorical_param"]["StringValue"] == "control-group", (
        f"expected 'control-group', got {parameters['categorical_param'].get('StringValue')!r}"
    )
    assert "StringValue" not in parameters["precise_metric"] or parameters["precise_metric"].get("StringValue") is None, (
        f"expected no StringValue on a NumberValue-only parameter, got {parameters['precise_metric'].get('StringValue')!r}"
    )


def _delete_trial_component(sm, trial_component_name):
    try:
        sm.delete_trial_component(TrialComponentName=trial_component_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFound":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
