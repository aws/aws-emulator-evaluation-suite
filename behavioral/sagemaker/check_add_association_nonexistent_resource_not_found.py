"""add-association-nonexistent-resource-not-found."""
from __future__ import annotations

import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "add-association-nonexistent-resource-not-found"
GROUP = "error-semantics"
SERVICES = ["sagemaker"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """AddAssociation to a well-formed nonexistent destination fails with ResourceNotFound and the exact
    message and records nothing, while an association between two real entities is echoed and listed."""
    sm = ctx.client("sagemaker")

    name_a = ctx.unique_name("sim2real-behav-art-a-")
    name_b = ctx.unique_name("sim2real-behav-art-b-")
    arn_a = sm.create_artifact(
        ArtifactName=name_a,
        ArtifactType="DataSet",
        Source={"SourceUri": f"s3://sim2real-behav-bucket/{name_a}", "SourceTypes": [{"SourceIdType": "Custom", "Value": "a"}]},
        Tags=[{"Key": "Name", "Value": name_a}],
    )["ArtifactArn"]
    ctx.on_cleanup(lambda: _delete_artifact_best_effort(sm, arn_a))
    arn_b = sm.create_artifact(
        ArtifactName=name_b,
        ArtifactType="DataSet",
        Source={"SourceUri": f"s3://sim2real-behav-bucket/{name_b}", "SourceTypes": [{"SourceIdType": "Custom", "Value": "b"}]},
        Tags=[{"Key": "Name", "Value": name_b}],
    )["ArtifactArn"]
    ctx.on_cleanup(lambda: _delete_artifact_best_effort(sm, arn_b))

    # positive control: association between two real artifacts succeeds
    resp = sm.add_association(SourceArn=arn_a, DestinationArn=arn_b, AssociationType="ContributedTo")
    assert resp["SourceArn"] == arn_a and resp["DestinationArn"] == arn_b, (
        f"expected the association response to echo {arn_a} -> {arn_b}, got {resp!r}"
    )
    ctx.on_cleanup(lambda: _delete_association_best_effort(sm, arn_a, arn_b))

    control_listing = sm.list_associations(SourceArn=arn_a)["AssociationSummaries"]
    assert any(a["DestinationArn"] == arn_b for a in control_listing), (
        f"expected an independent read to show {arn_a} -> {arn_b}, got {control_listing!r}"
    )

    # negative: destination ARN is well-formed (same account/region/resource-type) but
    # references an artifact that was never created
    bogus_destination = arn_b.rsplit("/", 1)[0] + "/" + uuid.uuid4().hex
    err = _client_error(
        lambda: sm.add_association(SourceArn=arn_a, DestinationArn=bogus_destination, AssociationType="ContributedTo")
    )
    assert err["Code"] == "ResourceNotFound", f"expected ResourceNotFound, got {err!r}"
    expected_message = f"Resource '{bogus_destination}' does not exist."
    assert err["Message"] == expected_message, (
        f"expected message {expected_message!r}, got {err.get('Message')!r}"
    )

    # effect absent: no association was actually recorded for the bogus destination
    outgoing = sm.list_associations(SourceArn=arn_a)["AssociationSummaries"]
    assert not any(a["DestinationArn"] == bogus_destination for a in outgoing), (
        "an association to a non-existent destination should not have been recorded"
    )


def _client_error(fn):
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


def _delete_artifact_best_effort(sm, arn):
    try:
        sm.delete_artifact(ArtifactArn=arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFound":
            raise


def _delete_association_best_effort(sm, source_arn, destination_arn):
    try:
        sm.delete_association(SourceArn=source_arn, DestinationArn=destination_arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFound":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
