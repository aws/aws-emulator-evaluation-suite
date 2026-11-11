"""s3-table-integration-source-association-lifecycle."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "s3-table-integration-source-association-lifecycle"
GROUP = "state-machine"
SERVICES = ["logs"]


def _never_ready(msg: str):
    """A resource accepted but never ready; returned so a call site keeps ``from exc`` chaining."""
    return AssertionError(msg)


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control", "resource:account-singleton:logs-s3-table-integration")
def run(ctx) -> None:
    """AssociateSourceToS3TableIntegration links a source visible via
    ListSourcesForS3TableIntegration and removed by DisassociateSourceFromS3TableIntegration;
    a failed IAM role or CreateS3TableIntegration prerequisite fails the check, never skips."""
    

    logs = ctx.client("logs")
    iam = ctx.client("iam")
    oadmin = ctx.client("observabilityadmin")

    log_group_name = ctx.unique_name("sim2real-behav-s3ti-lg-")
    logs.create_log_group(logGroupName=log_group_name, tags={"sim2real": CHECK})
    ctx.on_cleanup(lambda: logs.delete_log_group(logGroupName=log_group_name))

    role_name = ctx.unique_name("sim2real-behav-s3ti-role-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "logs.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    try:
        role = iam.create_role(
            RoleName=role_name,
            AssumeRolePolicyDocument=json.dumps(trust_policy),
            Tags=[{"Key": "sim2real", "Value": CHECK}],
        )
        role_arn = role["Role"]["Arn"]
        ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
        iam.put_role_policy(
            RoleName=role_name,
            PolicyName="s3-tables-access",
            PolicyDocument=json.dumps(
                {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Action": ["s3tables:*"],
                            "Resource": "*",
                        }
                    ],
                }
            ),
        )
        ctx.on_cleanup(
            lambda: iam.delete_role_policy(
                RoleName=role_name, PolicyName="s3-tables-access"
            )
        )
    except Exception as exc:  # noqa: BLE001
        raise AssertionError(f"could not provision prerequisite IAM role: {exc}")

    # A freshly created IAM role is not immediately usable cross-service
    # (eventual-consistency propagation lag), so CreateS3TableIntegration can
    # transiently fail with an access/validation error until the role
    # propagates. Poll the real condition -- the create call actually
    # succeeding -- in a bounded loop instead of guessing a fixed sleep.
    integration_arn = None
    create_exc = None

    def _try_create():
        nonlocal integration_arn, create_exc
        try:
            created = oadmin.create_s3_table_integration(
                RoleArn=role_arn,
                Encryption={"SseAlgorithm": "AES256"},
                Tags={"sim2real": CHECK},
            )
            integration_arn = created["Arn"]
            create_exc = None
        except Exception as exc:  # noqa: BLE001
            create_exc = exc
        return integration_arn

    _poll_until(_try_create, lambda arn: arn is not None, timeout_s=90.0, interval_s=5.0)
    if integration_arn is None:
        raise AssertionError(f"could not create S3 Table Integration prerequisite: {create_exc}")
    ctx.on_cleanup(lambda: oadmin.delete_s3_table_integration(Arn=integration_arn))

    status = _poll_until(
        lambda: oadmin.get_s3_table_integration(Arn=integration_arn)["Status"],
        lambda s: s == "ACTIVE",
        timeout_s=180.0,
        interval_s=5.0,
    )
    if status != "ACTIVE":
        raise _never_ready(
            f"S3 Table Integration never reached ACTIVE (last status={status})",
        )

    # Real AWS requires "type" on dataSource (rejected with a ValidationException on the
    # wire-level "sourceType" member even though it isn't marked required in the published
    # shape) and enforces the same lowercase letters/digits/underscores charset on "name" that
    # it enforces on log group names it does NOT allow (hyphens included) -- so the association
    # name has to be a separate, charset-compliant identifier from the log group name itself.
    source_name = ctx.unique_name("sim2reals3tisrc").lower()
    try:
        assoc = logs.associate_source_to_s3_table_integration(
            integrationArn=integration_arn,
            dataSource={"name": source_name, "type": "application_logs"},
        )
    except Exception as exc:  # noqa: BLE001
        raise AssertionError(f"could not associate a data source: {exc}")

    association_id = assoc["identifier"]
    assert association_id, f"AssociateSourceToS3TableIntegration returned no identifier: {assoc}"

    sources = logs.list_sources_for_s3_table_integration(integrationArn=integration_arn)
    names = [s.get("name") or s.get("dataSource", {}).get("name") for s in sources.get("sources", [])]
    assert source_name in names, f"associated source not visible in ListSourcesForS3TableIntegration: {sources}"

    logs.disassociate_source_from_s3_table_integration(identifier=association_id)

    # Disassociation is processed asynchronously on real AWS: the identifier can still briefly
    # appear in ListSourcesForS3TableIntegration immediately afterwards, so poll (bounded)
    # instead of asserting on a single immediate read.
    def _still_listed() -> bool:
        sources_after = logs.list_sources_for_s3_table_integration(integrationArn=integration_arn)
        names_after = [
            s.get("name") or s.get("dataSource", {}).get("name") for s in sources_after.get("sources", [])
        ]
        return source_name in names_after

    still_listed = _poll_until(_still_listed, lambda listed: not listed, timeout_s=60.0, interval_s=3.0)
    assert not still_listed, "source still listed after disassociation"

    # The association is now gone; disassociating the same (dead) identifier again must fail
    # with the specific not-found error, not silently succeed a second time.
    try:
        logs.disassociate_source_from_s3_table_integration(identifier=association_id)
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        message = exc.response["Error"].get("Message")
        assert code == "ResourceNotFoundException", (
            f"expected ResourceNotFoundException disassociating already-removed "
            f"identifier {association_id}, got {code!r}: {message!r}"
        )
        assert message == f"Association not found for identifier: {association_id}", (
            f"unexpected already-removed association message: {message!r}"
        )
    else:
        raise AssertionError(
            f"disassociating already-removed identifier {association_id} unexpectedly succeeded"
        )


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    return last


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
