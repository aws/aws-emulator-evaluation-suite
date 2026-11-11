"""collaboration-scoped-lists-empty-before-resources."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "collaboration-scoped-lists-empty-before-resources"
GROUP = "collaboration-scoping"
SERVICES = ["cleanroomsml"]


def _teardown(undo, *not_found: str):
    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A freshly joined collaboration with no ML resources at all returns an empty
    array (not an error, and with no nextToken) from every collaboration-scoped
    ML input channel, trained model and trained-model-inference-job listing."""
    cr = ctx.client("cleanrooms")
    crml = ctx.client("cleanroomsml")

    collab = cr.create_collaboration(
        name=ctx.unique_name("sim2real-crml-collab-"),
        description="behavioral fidelity check",
        members=[],
        creatorMemberAbilities=["CAN_QUERY", "CAN_RECEIVE_RESULTS"],
        creatorDisplayName="creator",
        queryLogStatus="DISABLED",
        tags={"sim2real": CHECK},
    )["collaboration"]
    collab_id = collab["id"]
    ctx.on_cleanup(_teardown(
        lambda: cr.delete_collaboration(collaborationIdentifier=collab_id), "ResourceNotFoundException"
    ))

    cr.create_membership(
        collaborationIdentifier=collab_id,
        queryLogStatus="DISABLED",
        tags={"sim2real": CHECK},
    )

    channels = crml.list_collaboration_ml_input_channels(collaborationIdentifier=collab_id)
    assert channels["collaborationMLInputChannelsList"] == [], (
        "expected no ML input channels on a fresh collaboration, got "
        f"{channels['collaborationMLInputChannelsList']!r}"
    )
    assert "nextToken" not in channels, f"expected no nextToken on an empty page, got {channels['nextToken']!r}"

    models = crml.list_collaboration_trained_models(collaborationIdentifier=collab_id)
    assert models["collaborationTrainedModels"] == [], (
        f"expected no trained models on a fresh collaboration, got {models['collaborationTrainedModels']!r}"
    )
    assert "nextToken" not in models, f"expected no nextToken on an empty page, got {models['nextToken']!r}"

    jobs = crml.list_collaboration_trained_model_inference_jobs(collaborationIdentifier=collab_id)
    assert jobs["collaborationTrainedModelInferenceJobs"] == [], (
        "expected no trained-model inference jobs on a fresh collaboration, got "
        f"{jobs['collaborationTrainedModelInferenceJobs']!r}"
    )
    assert "nextToken" not in jobs, f"expected no nextToken on an empty page, got {jobs['nextToken']!r}"

    associations = crml.list_collaboration_configured_model_algorithm_associations(
        collaborationIdentifier=collab_id
    )
    assert associations["collaborationConfiguredModelAlgorithmAssociations"] == [], (
        "expected no configured-model-algorithm associations on a fresh collaboration, got "
        f"{associations['collaborationConfiguredModelAlgorithmAssociations']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
