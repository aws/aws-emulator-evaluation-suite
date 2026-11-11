"""create-compute-quota-duplicate-name-conflict."""
from __future__ import annotations

import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-compute-quota-duplicate-name-conflict"
GROUP = "concurrency"
SERVICES = ["sagemaker"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateComputeQuota against a well-formed but nonexistent HyperPod cluster fails
    ValidationException, never ConflictException or success: cluster existence is checked before,
    and independently of, any duplicate-name handling."""
    sm = ctx.client("sagemaker")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    name = ctx.unique_name("sim2real-cq-dup-")
    fake_cluster_id = uuid.uuid4().hex[:12]
    cluster_arn = f"arn:aws:sagemaker:{ctx.region}:{account_id}:cluster/{fake_cluster_id}"
    team_name = _team_name(ctx)

    # ComputeQuotaConfig must be well-formed (ComputeQuotaResources populated) --
    # an empty {} draws its OWN ValidationException ("computeQuotaResources ...
    # must not be null") that has nothing to do with the cluster, which would
    # make this check pass for the wrong reason. With a well-formed config, the
    # only remaining problem is the fake ClusterArn.
    code, message = _error(
        lambda: sm.create_compute_quota(
            Name=name,
            ClusterArn=cluster_arn,
            ComputeQuotaConfig={"ComputeQuotaResources": [{"InstanceType": "ml.m5.large", "Count": 1}]},
            ComputeQuotaTarget={"TeamName": team_name},
        )
    )
    assert code == "ValidationException", f"expected ValidationException, got {code}"
    expected = "Specified cluster not found"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Effect absent: no quota was created under that name.
    describe_code, describe_message = _error(lambda: sm.describe_compute_quota(ComputeQuotaId=name))
    assert describe_code == "ValidationException", describe_code
    expected_describe = (
        f"1 validation error detected: Value '{name}' at 'computeQuotaId' failed to satisfy "
        "constraint: Member must satisfy regular expression pattern: [a-z0-9]{12}"
    )
    assert describe_message == expected_describe, (
        f"expected message {expected_describe!r}, got {describe_message!r}"
    )


def _team_name(ctx):
    raw = ctx.unique_name("sim2real-team-").lower().replace("_", "-")
    raw = raw[:40].strip("-")
    return raw


def _error(fn):
    """Call fn(); return its (code, message). An unexpected SUCCESS raises, because an emulator
    ACCEPTING input real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message", "")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

