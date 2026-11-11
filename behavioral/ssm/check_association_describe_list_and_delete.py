"""association-describe-list-and-delete."""
from __future__ import annotations

import json
import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "association-describe-list-and-delete"
GROUP = 'state-machine'
SERVICES = ['ssm']

@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeAssociation/ListAssociations reflect creation, and deletion is terminal."""

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

    def _error_or_success(fn):
        """Call fn(); return its ClientError (code, message), or ("<succeeded>", None) -- a
        value no error code equals. Used only inside a poll, where a transient success is
        expected during the consistency window."""
        try:
            fn()
        except ClientError as exc:
            error = exc.response.get("Error", {})
            return error.get("Code"), error.get("Message")
        return "<succeeded>", None

    def _expect_rejected(fn):
        """Call fn(); return its (code, message). An unexpected SUCCESS raises, because an
        over-permissive target accepting what real AWS refuses is the strongest signal available."""
        try:
            result = fn()
        except ClientError as exc:
            error = exc.response.get("Error", {})
            return error.get("Code"), error.get("Message")
        raise AssertionError(f"expected a ClientError, but the call SUCCEEDED: {result!r}")

    def _create_command_document(command="echo hello"):
        name = ctx.unique_name("sim2real-behav-probe-doc-")
        ctx.on_cleanup(lambda: ssm.delete_document(Name=name, Force=True))
        ssm.create_document(
            Content=_run_shell_doc_content(command),
            Name=name,
            DocumentType="Command",
            DocumentFormat="JSON",
            Tags=[{"Key": "sim2real", "Value": CHECK}],
        )
        _poll_until(
            lambda: ssm.describe_document(Name=name)["Document"]["Status"],
            lambda s: s in ("Active", "Failed"),
            timeout_s=60,
            interval_s=1,
        )
        return name

    doc_name = _create_command_document()
    assoc_name = ctx.unique_name("sim2real-behav-assoc-").replace(".", "-")
    assoc = ssm.create_association(
        Name=doc_name,
        Targets=[{"Key": "tag:" + ctx.unique_name("k-"), "Values": ["nomatch"]}],
        ScheduleExpression="rate(30 minutes)",
        AssociationName=assoc_name,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["AssociationDescription"]
    association_id = assoc["AssociationId"]
    def _delete_association_if_exists():
        try:
            ssm.delete_association(AssociationId=association_id)
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "AssociationDoesNotExist":
                raise

    ctx.on_cleanup(_delete_association_if_exists)

    described = ssm.describe_association(AssociationId=association_id)[
        "AssociationDescription"
    ]
    assert described["Name"] == doc_name, described
    assert described["AssociationVersion"] == "1", described
    assert described["ScheduleExpression"] == "rate(30 minutes)", described

    listed = ssm.list_associations(
        AssociationFilterList=[{"key": "Name", "value": doc_name}]
    )["Associations"]
    assert any(a["AssociationId"] == association_id for a in listed), listed

    executions = ssm.describe_association_executions(AssociationId=association_id)[
        "AssociationExecutions"
    ]
    assert isinstance(executions, list), executions

    # Positive control: StartAssociationsOnce accepts the real association id — this is
    # what makes the bogus-id rejection below mean something more specific than "this
    # account rejects every StartAssociationsOnce call".
    ssm.start_associations_once(AssociationIds=[association_id])

    # StartAssociationsOnce must reject an unknown association id.
    bogus = str(uuid.uuid4())
    code, message = _expect_rejected(lambda: ssm.start_associations_once(AssociationIds=[bogus]))
    assert code == "AssociationDoesNotExist", code
    expected = f"Association id {bogus} does not exist"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    ssm.delete_association(AssociationId=association_id)
    # Deletion is terminal but eventually consistent: DescribeAssociation may
    # still succeed for a short window before it reports AssociationDoesNotExist.
    _, gone_message = _poll_until(
        lambda: _error_or_success(lambda: ssm.describe_association(AssociationId=association_id)),
        lambda err: err[0] == "AssociationDoesNotExist",
        timeout_s=60,
        interval_s=2,
    )
    expected = f"Association {association_id} does not exist."
    assert gone_message == expected, f"expected message {expected!r}, got {gone_message!r}"

    # The dead id is not just unreadable, it is unusable: a mutating call against it
    # fails with the same specific not-found code, not a generic success or 500.
    dead_code, dead_message = _expect_rejected(
        lambda: ssm.start_associations_once(AssociationIds=[association_id])
    )
    assert dead_code == "AssociationDoesNotExist", dead_code
    expected = f"Association id {association_id} does not exist"
    assert dead_message == expected, f"expected message {expected!r}, got {dead_message!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
