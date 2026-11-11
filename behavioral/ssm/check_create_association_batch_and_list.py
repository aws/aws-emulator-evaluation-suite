"""create-association-batch-and-list."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-association-batch-and-list"
GROUP = "state-machine"
SERVICES = ["ssm"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateAssociationBatch with two entries reports no Failed entries and two Successful associations, one per
    document, and ListAssociations returns both association ids."""
    ssm = ctx.client("ssm")
    doc1 = _create_command_document(ctx)
    doc2 = _create_command_document(ctx)

    # A run-unique tag no managed node carries: the association targets no instance.
    no_node = [{"Key": "tag:sim2real-target", "Values": [ctx.unique_name("sim2real-no-node-")]}]
    resp = ssm.create_association_batch(
        Entries=[
            {"Name": doc1, "Targets": no_node},
            {"Name": doc2, "Targets": no_node},
        ]
    )
    assert resp.get("Failed", []) == [], resp.get("Failed")
    successful = resp["Successful"]
    assert len(successful) == 2, successful
    ids_by_name = {s["Name"]: s["AssociationId"] for s in successful}
    assert set(ids_by_name.keys()) == {doc1, doc2}, (ids_by_name, doc1, doc2)
    target_ids = set(ids_by_name.values())
    for assoc_id in target_ids:
        ctx.on_cleanup(lambda a=assoc_id: _delete_association_if_exists(ssm, a))
        ssm.add_tags_to_resource(
            ResourceType="Association",
            ResourceId=assoc_id,
            Tags=[{"Key": "sim2real-check", "Value": CHECK}],
        )

    found_ids = _list_target_ids_until_visible(ssm, target_ids)
    assert found_ids == target_ids, (found_ids, target_ids)


def _create_command_document(ctx) -> str:
    ssm = ctx.client("ssm")
    name = ctx.unique_name("sim2real-ssm-doc-")
    content = json.dumps(
        {
            "schemaVersion": "2.2",
            "description": "sim2real behavioral test document",
            "mainSteps": [
                {
                    "action": "aws:runShellScript",
                    "name": "echoStep",
                    "inputs": {"runCommand": ["echo sim2real"]},
                }
            ],
        }
    )
    ssm.create_document(
        Content=content,
        Name=name,
        DocumentType="Command",
        DocumentFormat="JSON",
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: ssm.delete_document(Name=name, Force=True))
    return name


def _list_target_ids_until_visible(ssm, target_ids: set, timeout_s: float = 60.0, interval_s: float = 2.0) -> set:
    """ListAssociations is backed by an eventually-consistent index, so a
    freshly batch-created association may not appear on the very next list
    call. Walk the full page set on each attempt and retry until every
    target id has been observed or the deadline passes."""
    deadline = time.monotonic() + timeout_s
    found_ids: set = set()
    while True:
        found_ids = set()
        next_token = None
        while True:
            kwargs = {"NextToken": next_token} if next_token else {}
            page = ssm.list_associations(**kwargs)
            for a in page.get("Associations", []):
                if a.get("AssociationId") in target_ids:
                    found_ids.add(a["AssociationId"])
            next_token = page.get("NextToken")
            if not next_token:
                break
        if found_ids == target_ids or time.monotonic() >= deadline:
            return found_ids
        time.sleep(interval_s)


def _delete_association_if_exists(ssm, assoc_id: str) -> None:
    try:
        ssm.delete_association(AssociationId=assoc_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "AssociationDoesNotExist":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
