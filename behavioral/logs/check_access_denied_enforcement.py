"""access-denied-enforcement."""
from __future__ import annotations

import json
import time
import uuid
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "access-denied-enforcement"
GROUP = 'log-group-lifecycle'
SERVICES = ['logs']


@tags("axis:rejection", "cap:c7", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A role with no attached policy gets AccessDeniedException (or the operation's listed alternative refusal)
    from each listed elevated-permission Logs operation, while the default caller is not denied on any of them:
    an implicit deny is never answered as not-found or empty."""
    iam = ctx.client("iam")
    sts = ctx.client("sts")
    full_client = ctx.client("logs")
    account = sts.get_caller_identity()["Account"]

    fake_id = ctx.unique_name("sim2real-behav-denied-")
    fake_group_arn = f"arn:aws:logs:{ctx.region}:{account}:log-group:{fake_id}"
    fake_source_arn = f"arn:aws:cloudtrail:{ctx.region}:{account}:eventdatastore/{uuid.uuid4()}"
    fake_role_arn = f"arn:aws:iam::{account}:role/{ctx.unique_name('sim2real-behav-denied-role-')}"
    now = int(time.time())

    # method name, kwargs and the acceptable rejection codes for a ZERO-permission
    # caller. Most operations hit the IAM authorizer before any business-logic
    # parameter validation, so a garbage-but-required identifier still comes back
    # AccessDeniedException. A few validate shape/signature FIRST — both
    # InvalidParameterException and UnrecognizedClientException are recorded as
    # ADDITIONAL acceptable "this zero-permission caller was rejected, not served"
    # outcomes for exactly those operations.
    ops: dict[str, tuple[str, dict[str, Any], tuple[str, ...]]] = {
        "CreateImportTask": (
            "create_import_task",
            {"importSourceArn": fake_source_arn, "importRoleArn": fake_role_arn},
            ("AccessDeniedException", "UnrecognizedClientException"),
        ),
        "CancelImportTask": ("cancel_import_task", {"importId": fake_id}, ("AccessDeniedException",)),
        "DescribeImportTasks": ("describe_import_tasks", {}, ("AccessDeniedException",)),
        "DescribeImportTaskBatches": (
            "describe_import_task_batches",
            {"importId": fake_id},
            ("AccessDeniedException",),
        ),
        "DeleteScheduledQuery": ("delete_scheduled_query", {"identifier": fake_id}, ("AccessDeniedException",)),
        "GetScheduledQuery": ("get_scheduled_query", {"identifier": fake_id}, ("AccessDeniedException",)),
        "GetScheduledQueryHistory": (
            "get_scheduled_query_history",
            {"identifier": fake_id, "startTime": now - 3600, "endTime": now},
            ("AccessDeniedException", "UnrecognizedClientException"),
        ),
        "ListScheduledQueries": ("list_scheduled_queries", {}, ("AccessDeniedException",)),
        "PutSyslogConfiguration": (
            "put_syslog_configuration",
            {"logGroupIdentifier": fake_id},
            ("AccessDeniedException",),
        ),
        "DeleteSyslogConfiguration": (
            "delete_syslog_configuration",
            {"logGroupIdentifier": fake_id},
            ("AccessDeniedException",),
        ),
        "ListSyslogConfigurations": ("list_syslog_configurations", {}, ("AccessDeniedException",)),
        "PutBearerTokenAuthentication": (
            "put_bearer_token_authentication",
            {"logGroupIdentifier": fake_id, "bearerTokenAuthenticationEnabled": True},
            ("AccessDeniedException",),
        ),
        "StartLiveTail": (
            "start_live_tail",
            {"logGroupIdentifiers": [fake_group_arn]},
            ("AccessDeniedException", "InvalidParameterException"),
        ),
        "GetLogObject": (
            "get_log_object",
            {"logObjectPointer": "bogus-pointer"},
            ("AccessDeniedException", "InvalidParameterException"),
        ),
    }

    # Positive control: the SAME calls, made with the harness's normally permissioned client, must
    # never come back AccessDeniedException. Without this leg, "denied" is indistinguishable from
    # "every caller is rejected regardless of permission" — this proves the account/credentials are
    # otherwise healthy for every one of these operations before we test that a zero-permission
    # caller specifically is the one being denied.
    control_failures: dict[str, str] = {}
    for op_name, (method_name, kwargs, _codes) in ops.items():
        try:
            getattr(full_client, method_name)(**kwargs)
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code == "AccessDeniedException":
                control_failures[op_name] = "positive control (full permissions) also got AccessDeniedException"
        except Exception:  # noqa: BLE001 — anything other than AccessDenied is fine here
            pass
    assert not control_failures, (
        f"operations that reject even a fully-permissioned caller, so they cannot serve as an "
        f"IAM-denial control: {control_failures!r}"
    )

    # A REAL IAM role, assumable by our own account root, with NO permissions
    # policy attached — assuming it and calling ANY action must implicit-deny.
    role_name = ctx.unique_name("sim2real-behav-nopriv-accessdenied-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{account}:root"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
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
    role_arn = f"arn:aws:iam::{account}:role/{role_name}"

    # AssumeRole, retrying past IAM's brief propagation delay for a just-created
    # role/trust-policy, then build a logs client from the temporary creds.
    deadline = time.monotonic() + 30
    creds = None
    last_exc: Exception | None = None
    while time.monotonic() < deadline:
        try:
            creds = sts.assume_role(RoleArn=role_arn, RoleSessionName="sim2real-behav")["Credentials"]
            break
        except Exception as exc:  # noqa: BLE001 — retry past propagation delay
            last_exc = exc
            time.sleep(3.0)
    if creds is None:
        raise AssertionError(f"AssumeRole({role_arn}) never succeeded, cannot exercise a zero-permission caller: {last_exc!r}")

    denied_client = ctx.client(
        "logs",
        creds={
            "aws_access_key_id": creds["AccessKeyId"],
            "aws_secret_access_key": creds["SecretAccessKey"],
            "aws_session_token": creds["SessionToken"],
        },
    )

    failures: dict[str, str] = {}
    for op_name, (method_name, kwargs, acceptable_codes) in ops.items():
        try:
            getattr(denied_client, method_name)(**kwargs)
            failures[op_name] = "SUCCEEDED (expected a rejection)"
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code not in acceptable_codes:
                failures[op_name] = f"wrong error code: {code!r} (expected one of {acceptable_codes!r})"
        except Exception as exc:  # noqa: BLE001
            failures[op_name] = f"unexpected exception: {exc!r}"

    assert not failures, (
        f"operations that did NOT return an acceptable rejection code for a zero-permission caller: {failures!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
