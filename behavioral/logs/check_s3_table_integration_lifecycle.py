"""s3-table-integration-lifecycle."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "s3-table-integration-lifecycle"
GROUP = 'data-plane'
SERVICES = ['logs']


def _error_code(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises, because
    an over-permissive target accepting input real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {}).get("Code"), exc.response.get("Error", {}).get("Message")
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")


def _ignore_notfound(fn):
    """Teardown: the check deletes the integration itself, so a second delete is not-found."""
    try:
        fn()
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise


def _poll_until(probe, predicate, *, timeout_s=60, interval_s=1.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:logs-s3-table-integration")
def run(ctx) -> None:
    """A new S3 Table Integration lists no sources; a valid association is listed and removable, a
    wrong-case source type is refused with ValidationException, and after the integration is deleted
    listing and disassociating are refused with their exact messages.
    """
    svc = ctx.client("logs")
    iam = ctx.client("iam")
    obs = ctx.client("observabilityadmin")
    account = ctx.client("sts").get_caller_identity()["Account"]

    # A REAL IAM role trusted by logs.amazonaws.com (scoped to this account)
    # granting logs:integrateWithS3Table — the service role CloudWatch Logs
    # assumes to write vended log data into S3 Tables.
    role_name = ctx.unique_name("sim2real-behav-s3trole-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "logs.amazonaws.com"},
                "Action": "sts:AssumeRole",
                "Condition": {"StringEquals": {"aws:SourceAccount": account}},
            }
        ],
    }
    iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )

    def _delete_role(_n=role_name):
        try:
            for pname in iam.list_role_policies(RoleName=_n).get("PolicyNames", []):
                try:
                    iam.delete_role_policy(RoleName=_n, PolicyName=pname)
                except ClientError as exc:
                    if exc.response["Error"]["Code"] != "NoSuchEntity":
                        raise
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
        iam.delete_role(RoleName=_n)

    ctx.on_cleanup(_delete_role)
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName="allow-s3-table-write",
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {"Effect": "Allow", "Action": ["logs:integrateWithS3Table"], "Resource": "*"}
                ],
            }
        ),
    )
    role_arn = f"arn:aws:iam::{account}:role/{role_name}"

    integ_arn = _poll_until(
        lambda: obs.create_s3_table_integration(
            Encryption={"SseAlgorithm": "AES256"},
            RoleArn=role_arn,
            Tags={"sim2real:managed": "true"},
        ),
        lambda r: bool(r.get("Arn")),
        timeout_s=30,
        interval_s=5.0,
        description="S3 Table Integration is created",
    )["Arn"]
    ctx.on_cleanup(lambda _a=integ_arn: _ignore_notfound(lambda: obs.delete_s3_table_integration(Arn=_a)))

    listed = svc.list_sources_for_s3_table_integration(integrationArn=integ_arn)
    assert listed.get("sources", []) == [], (
        f"expected a freshly-created integration to have no sources, got {listed!r}"
    )

    # POSITIVE CONTROL: a well-formed associate call against this real
    # integration ARN succeeds. Without this, every rejection below is
    # indistinguishable from a target that rejects the operation outright.
    good_name = ctx.unique_name("sim2realbehavs3tiprobe").lower()
    good_identifier = svc.associate_source_to_s3_table_integration(
        integrationArn=integ_arn,
        dataSource={"name": good_name, "type": "application_logs"},
    )["identifier"]
    assert good_identifier, "AssociateSourceToS3TableIntegration returned no identifier"
    after_assoc = svc.list_sources_for_s3_table_integration(integrationArn=integ_arn)
    assoc_identifiers = [s["identifier"] for s in after_assoc.get("sources", [])]
    assert good_identifier in assoc_identifiers, (
        f"{good_identifier} missing from ListSourcesForS3TableIntegration: {after_assoc!r}"
    )

    # The same recognized category in the wrong case is rejected outright (not silently
    # normalized), even against this real integration ARN the positive control used above.
    case_code, case_message = _error_code(
        lambda: svc.associate_source_to_s3_table_integration(
            integrationArn=integ_arn,
            dataSource={"name": ctx.unique_name("sim2realbehavs3ticase").lower(), "type": "APPLICATION_LOGS"},
        )
    )
    assert case_code == "ValidationException", f"expected ValidationException, got {case_code!r}"
    assert case_message == "Source type must only contain letters, numbers, and underscores", (
        f"unexpected wrong-case source type message: {case_message!r}"
    )

    # A well-formatted but made-up category is ACCEPTED: ``type`` is a spelling
    # check, not a fixed category enum. The check disassociates it itself, as it
    # is a second real association alongside good_identifier.
    freeform_identifier = svc.associate_source_to_s3_table_integration(
        integrationArn=integ_arn,
        dataSource={
            "name": ctx.unique_name("sim2realbehavs3tifreeform").lower(),
            "type": "sim2real_not_a_real_category",
        },
    )["identifier"]
    assert freeform_identifier, (
        "AssociateSourceToS3TableIntegration with an unrecognized-but-well-formatted "
        "type unexpectedly failed to return an identifier"
    )
    svc.disassociate_source_from_s3_table_integration(identifier=freeform_identifier)

    # POSITIVE CONTROL for the disassociate rejection below: disassociating a
    # REAL identifier succeeds and the source disappears from the independent
    # list read (disassociation is processed asynchronously on real AWS, so
    # poll rather than assert on a single immediate read).
    svc.disassociate_source_from_s3_table_integration(identifier=good_identifier)

    def _list_identifiers():
        after = svc.list_sources_for_s3_table_integration(integrationArn=integ_arn)
        return [s["identifier"] for s in after.get("sources", [])]

    after_disassoc = _poll_until(
        _list_identifiers,
        lambda ids: good_identifier not in ids,
        timeout_s=60,
        interval_s=3.0,
        description=f"{good_identifier} removed from ListSourcesForS3TableIntegration",
    )
    assert good_identifier not in after_disassoc, (
        f"{good_identifier} still present after disassociate: {after_disassoc!r}"
    )

    # Delete the integration so its ARN serves as a nonexistent but
    # correctly shaped ARN for the not-found boundary below.
    obs.delete_s3_table_integration(Arn=integ_arn)

    def _probe_deleted_arn_error():
        # Unlike _error_code, this tolerates a transient SUCCESS: right after
        # delete, ListSourcesForS3TableIntegration can still briefly resolve
        # the deleted ARN, and that eventual-consistency window is exactly
        # what the poll below is waiting out -- it is not itself the verdict.
        try:
            svc.list_sources_for_s3_table_integration(integrationArn=integ_arn)
        except ClientError as exc:
            return exc.response.get("Error", {}).get("Code"), exc.response.get("Error", {}).get("Message")
        return None

    list_code, list_message = _poll_until(
        _probe_deleted_arn_error,
        lambda c: c is not None,
        timeout_s=60,
        interval_s=5.0,
        description="ListSourcesForS3TableIntegration rejects the deleted integration ARN",
    )
    assert list_code == "ValidationException", f"expected ValidationException, got {list_code!r}"
    assert list_message == f"Integration not found: {integ_arn}", (
        f"unexpected deleted-integration message: {list_message!r}"
    )

    disassoc_code, disassoc_message = _error_code(
        lambda: svc.disassociate_source_from_s3_table_integration(
            identifier="sim2real-behav-nonexistent-association"
        )
    )
    assert disassoc_code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException, got {disassoc_code!r}"
    )
    assert disassoc_message == (
        "Association not found for identifier: sim2real-behav-nonexistent-association"
    ), f"unexpected nonexistent-association message: {disassoc_message!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
