"""create-compute-quota-negative-limit-rejected."""
from __future__ import annotations

from botocore.config import Config
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-compute-quota-negative-limit-rejected"
GROUP = "overly-permissive"
SERVICES = ["sagemaker"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateComputeQuota with Count -5 (client validation off) fails with ValidationException naming
    the count and -5 and persists nothing, while the same call with a valid Count fails on the
    cluster instead ('Specified cluster not found'), so the first refusal is about the count."""
    sm = ctx.client("sagemaker")
    unvalidated = ctx.client("sagemaker", config=Config(parameter_validation=False))
    account = ctx.client("sts").get_caller_identity()["Account"]
    fake_cluster_arn = f"arn:aws:sagemaker:{ctx.region}:{account}:cluster/000000000000"

    bad_name = ctx.unique_name("sim2real-behav-cq-bad-")
    error = _client_error(
        lambda: unvalidated.create_compute_quota(
            Name=bad_name,
            ClusterArn=fake_cluster_arn,
            ComputeQuotaConfig={"ComputeQuotaResources": [{"InstanceType": "ml.c5.xlarge", "Count": -5}]},
            ComputeQuotaTarget={"TeamName": "sim2real-team"},
        )
    )
    assert error.get("Code") == "ValidationException", (
        f"expected ValidationException, got {error.get('Code')!r}"
    )
    message = error.get("Message", "")
    assert "-5" in message and "count" in message.lower(), (
        f"expected a count-specific rejection naming the -5 value, got {message!r}"
    )

    listed = sm.list_compute_quotas(NameContains=bad_name)
    names = [q["Name"] for q in listed.get("ComputeQuotaSummaries", [])]
    assert bad_name not in names, "a compute quota with a negative Count was persisted"

    # Positive control: the identical request shape with a VALID Count against the SAME
    # cluster ARN must advance past the count check -- proven by a DIFFERENT, later-stage
    # rejection reason (cluster resolution) instead of repeating the count-specific message.
    control_name = ctx.unique_name("sim2real-behav-cq-ctrl-")
    control_error = _client_error(
        lambda: sm.create_compute_quota(
            Name=control_name,
            ClusterArn=fake_cluster_arn,
            ComputeQuotaConfig={"ComputeQuotaResources": [{"InstanceType": "ml.c5.xlarge", "Count": 1}]},
            ComputeQuotaTarget={"TeamName": "sim2real-team"},
        )
    )
    assert control_error.get("Code") == "ValidationException", (
        f"expected the valid-count control to also fail with ValidationException (cluster "
        f"resolution), got {control_error.get('Code')!r}"
    )
    assert control_error.get("Message") == "Specified cluster not found", (
        f"expected the valid-count control to fail on cluster resolution with 'Specified "
        f"cluster not found' -- an identical message to the negative-count rejection would "
        f"mean the count check is not actually gating anything; got "
        f"{control_error.get('Message')!r}"
    )

    control_listed = sm.list_compute_quotas(NameContains=control_name)
    control_names = [q["Name"] for q in control_listed.get("ComputeQuotaSummaries", [])]
    assert control_name not in control_names, (
        "a compute quota referencing a non-existent cluster was persisted"
    )


def _client_error(fn):
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises, because an emulator
    ACCEPTING input real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
