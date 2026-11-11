"""get-lineage-group-policy-missing."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-lineage-group-policy-missing"
GROUP = "error-semantics"
SERVICES = ["sagemaker"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetLineageGroupPolicy on a lineage group name that does not exist returns ResourceNotFound with its
    exact message, while the account's default lineage group describes on the same client.
    """
    sm = ctx.client("sagemaker")

    real_name = _default_lineage_group_name(sm, ctx)
    desc = sm.describe_lineage_group(LineageGroupName=real_name)
    assert desc["LineageGroupName"] == real_name, (
        f"positive control failed: describing {real_name!r} returned "
        f"{desc.get('LineageGroupName')!r}"
    )

    name = ctx.unique_name("sim2real-lineage-")[:63]
    code, message = _error(lambda: sm.get_lineage_group_policy(LineageGroupName=name))
    assert code == "ResourceNotFound", f"expected ResourceNotFound, got {code}"
    assert message == (
        f"LineageGroup 'arn:aws:sagemaker:{ctx.region}:{ctx.account}:lineage-group/{name}' does not exist."
    ), f"unexpected GetLineageGroupPolicy message: {message!r}"


def _error(fn):
    """The AWS (code, message) raised by fn(); an unexpected SUCCESS raises, so a target that
    accepts what AWS refuses fails loudly rather than reading as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded and returned {result!r}")


def _default_lineage_group_name(sm, ctx):
    """The account's default lineage group, provisioned by one throwaway Artifact (deleted at
    teardown) when ListLineageGroups lists none; SageMaker has no public CreateLineageGroup."""
    groups = sm.list_lineage_groups().get("LineageGroupSummaries", [])
    if groups:
        return groups[0]["LineageGroupName"]

    name = ctx.unique_name("sim2real-lineage-trigger-")
    created = sm.create_artifact(
        ArtifactName=name,
        Source={"SourceUri": f"s3://sim2real-lineage-trigger/{name}"},
        ArtifactType="DataSet",
        Tags=[{"Key": "sim2real:check", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: sm.delete_artifact(ArtifactArn=created["ArtifactArn"]))

    left = ctx.time_left()
    deadline = time.monotonic() + (60.0 if left is None else max(1.0, min(60.0, left - 5.0)))
    while True:
        groups = sm.list_lineage_groups().get("LineageGroupSummaries", [])
        if groups:
            return groups[0]["LineageGroupName"]
        if time.monotonic() >= deadline:
            left = ctx.time_left()
            if left is not None and left <= 6.0:
                raise TimeoutError("default lineage group: the run budget ended first; not graded")
            raise AssertionError(
                "ListLineageGroups is still empty after creating a lineage artifact in "
                "this account/region, which on real AWS is enough to provision the "
                "account's default lineage group; there is nothing to probe "
                "GetLineageGroupPolicy against."
            )
        time.sleep(2)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
