"""create-custom-action-type-too-many-tags-fails."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-custom-action-type-too-many-tags-fails"
GROUP = 'overly-permissive'
SERVICES = ['codepipeline']

_ARTIFACT_DETAILS = {'minimumCount': 0, 'maximumCount': 1}


def _track_action_type(client, ctx, category, provider, version):
    """Register a best-effort DeleteCustomActionType cleanup for a manually-created action type."""
    ctx.on_cleanup(
        lambda: client.delete_custom_action_type(category=category, provider=provider, version=version)
    )


def _custom_providers(client):
    providers = set()
    paginator = client.get_paginator("list_action_types")
    for page in paginator.paginate(actionOwnerFilter="Custom"):
        for at in page.get("actionTypes", []):
            providers.add(at["id"]["provider"])
    return providers


def _action_type_arn(ctx, owner, category, provider, version):
    account = ctx.client("sts").get_caller_identity()["Account"]
    return f"arn:aws:codepipeline:{ctx.region}:{account}:actiontype:{owner}/{category}/{provider}/{version}"


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateCustomActionType accepts exactly the 50-tag ceiling and rejects 51
    with TooManyTagsException, with no action type created for the rejected call."""
    ev = ctx.client("codepipeline")

    # Positive control: exactly the 50-tag limit is accepted and the tags round-trip
    # through an independent ListTagsForResource read.
    ok_provider = ctx.unique_name("sim2real-behav-caok-")
    ok_tags = [{"key": f"probe-key-{i}", "value": f"v{i}"} for i in range(50)]
    ev.create_custom_action_type(
        category="Build", provider=ok_provider, version="1",
        inputArtifactDetails=_ARTIFACT_DETAILS, outputArtifactDetails=_ARTIFACT_DETAILS,
        tags=ok_tags,
    )
    _track_action_type(ev, ctx, "Build", ok_provider, "1")
    assert ok_provider in _custom_providers(ev), f"{ok_provider} missing from ListActionTypes"
    ok_arn = _action_type_arn(ctx, "Custom", "Build", ok_provider, "1")
    got_tags = ev.list_tags_for_resource(resourceArn=ok_arn)["tags"]
    assert {(t["key"], t["value"]) for t in got_tags} == {(t["key"], t["value"]) for t in ok_tags}, got_tags

    # Negative: 51 tags exceeds the 50-tag ceiling and the request must fail before
    # any action type is created.
    provider = ctx.unique_name("sim2real-behav-ca-tags-")
    too_many = [{"key": f"probe-key-{i}", "value": f"v{i}"} for i in range(51)]
    try:
        ev.create_custom_action_type(
            category='Build', provider=provider, version='1',
            inputArtifactDetails=_ARTIFACT_DETAILS, outputArtifactDetails=_ARTIFACT_DETAILS,
            tags=too_many,
        )
        _track_action_type(ev, ctx, "Build", provider, "1")
        raise AssertionError("CreateCustomActionType with 51 tags must be rejected")
    except ClientError as exc:
        err = exc.response["Error"]
        assert (err.get("Code"), err.get("Message")) == (
            "TooManyTagsException",
            f"Tag limit exceeded for custom action type with category=[Build], provider=[{provider}] "
            "and version=[1].",
        ), err

    assert provider not in _custom_providers(ev), (
        f"{provider} must not have been created for the rejected request"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
