"""association-create-update-versioning."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "association-create-update-versioning"
GROUP = 'state-machine'
SERVICES = ['ssm']

@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateAssociation starts at AssociationVersion 1, UpdateAssociation with a new schedule
    returns version 2, and ListAssociationVersions returns both versions with their own
    ScheduleExpression."""

    ssm = ctx.client("ssm")

    def _run_shell_doc_content(command="echo hello"):
        return json.dumps(
            {
                "schemaVersion": "2.2",
                "description": "behavioral-fidelity-probe document",
                "mainSteps": [
                    {
                        "action": "aws:runShellScript",
                        "name": "runShellScript",
                        "inputs": {"runCommand": [command]},
                    }
                ],
            }
        )

    def _poll_until(probe, predicate, *, timeout_s=60, interval_s=1.0):
        deadline = time.monotonic() + timeout_s
        last = None
        while time.monotonic() < deadline:
            last = probe()
            if predicate(last):
                return last
            time.sleep(interval_s)
        raise AssertionError(f"condition not met within {timeout_s}s. Last: {last!r}")

    def _create_command_document(command="echo hello"):
        name = ctx.unique_name("sim2real-behav-probe-doc-")
        ctx.on_cleanup(lambda: ssm.delete_document(Name=name, Force=True))
        ssm.create_document(
            Content=_run_shell_doc_content(command),
            Name=name,
            DocumentType="Command",
            DocumentFormat="JSON",
            Tags=[{"Key": "sim2real-check", "Value": CHECK}],
        )
        _poll_until(
            lambda: ssm.describe_document(Name=name)["Document"]["Status"],
            lambda s: s in ("Active", "Failed"),
            timeout_s=60,
            interval_s=1,
        )
        return name

    def _track_association(association_id):
        ctx.on_cleanup(lambda: ssm.delete_association(AssociationId=association_id))
        return association_id

    doc_name = _create_command_document()

    # A run-unique tag no managed node carries: the association targets no instance.
    no_node = [{"Key": "tag:sim2real-target", "Values": [ctx.unique_name("sim2real-no-node-")]}]
    create_resp = ssm.create_association(
        Name=doc_name,
        Targets=no_node,
        ScheduleExpression="rate(30 minutes)",
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    assoc = create_resp["AssociationDescription"]
    association_id = assoc["AssociationId"]
    _track_association(association_id)
    assert assoc["AssociationVersion"] == "1", assoc

    update_resp = ssm.update_association(
        AssociationId=association_id, ScheduleExpression="rate(60 minutes)"
    )
    updated = update_resp["AssociationDescription"]
    assert updated["AssociationVersion"] == "2", updated
    assert updated["ScheduleExpression"] == "rate(60 minutes)", updated

    # Terminal read: an independent operation (ListAssociationVersions), not the
    # mutating calls' own responses. It must show both versions still exist AND
    # that each version's ScheduleExpression matches what was true when that
    # version was created -- proving history is retained, not just IDs bumped.
    versions = ssm.list_association_versions(AssociationId=association_id)[
        "AssociationVersions"
    ]
    version_numbers = {v["AssociationVersion"] for v in versions}
    assert version_numbers == {"1", "2"}, version_numbers
    by_version = {v["AssociationVersion"]: v for v in versions}
    assert by_version["1"]["ScheduleExpression"] == "rate(30 minutes)", by_version["1"]
    assert by_version["2"]["ScheduleExpression"] == "rate(60 minutes)", by_version["2"]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
