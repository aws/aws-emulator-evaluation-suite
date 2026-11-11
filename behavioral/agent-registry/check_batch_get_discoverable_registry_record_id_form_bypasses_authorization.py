"""batch-get-discoverable-registry-record-id-form-bypasses-authorization."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "batch-get-discoverable-registry-record-id-form-bypasses-authorization"
GROUP = 'error-semantics'
SERVICES = ['agent-registry']


def _error(fn):
    """(Error.Code, Error.Message) of the ClientError fn() raises; an unexpected success fails."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _delete_role(iam, role_name):
    try:
        iam.delete_role(RoleName=role_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _restricted_client(ctx, service, max_attempts=12):
    """An IAM role trusted by this account's root, with no permissions policy, assumed, and
    returned as a `service` client signing with those temporary credentials: any call
    through it is guaranteed to be rejected for lack of permission."""
    iam = ctx.client("iam")
    sts = ctx.client("sts")
    account_id = ctx.account
    role_name = ctx.unique_name("sim2real-behav-restricted-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: _delete_role(iam, role_name))
    session_name = ctx.unique_name("sess-")[:64]
    creds = None
    last_exc = None
    for _ in range(max_attempts):
        try:
            creds = sts.assume_role(RoleArn=role_arn, RoleSessionName=session_name)["Credentials"]
            break
        except ClientError as exc:
            last_exc = exc
            time.sleep(2)
    if creds is None:
        assert last_exc is not None
        raise last_exc
    cred_kwargs = {
        "aws_access_key_id": creds["AccessKeyId"],
        "aws_secret_access_key": creds["SecretAccessKey"],
        "aws_session_token": creds["SessionToken"],
    }
    probe = ctx.client("sts", creds=cred_kwargs)
    for _ in range(max_attempts):
        try:
            probe.get_caller_identity()
            break
        except ClientError:
            time.sleep(2)
    return ctx.client(service, creds=cred_kwargs)


def _refusal_once_credentials_settle(fn, attempts=15):
    """_error(fn), retried while fresh assumed-role credentials are still unknown to the
    service (UnrecognizedClientException); the last refusal is returned after ``attempts``."""
    code, message = _error(fn)
    for _ in range(attempts):
        if code != "UnrecognizedClientException":
            break
        time.sleep(2)
        code, message = _error(fn)
    return code, message


@tags("axis:rejection", "cap:c7", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """BatchGetDiscoverableRegistryRecord only evaluates resource-level authorization when the
    caller names the registry by its full ARN. Naming the identical registry by its plain ID
    skips that check and reaches the same not-found answer a fully-permissioned caller gets.
    """
    ar = ctx.client("agent-registry")
    account_id = ctx.account
    region = ctx.region
    missing_id = "sim2realnotfnd1"
    missing_arn = f"arn:aws:agent-registry:{region}:{account_id}:registry/{missing_id}"
    record_id = "sim2real0001"
    malformed_record_id = "!!!"

    control_code, control_message = _error(
        lambda: ar.batch_get_discoverable_registry_record(
            entries=[{"registryId": missing_id, "recordIds": [record_id]}]
        )
    )
    assert control_code == "ResourceNotFoundException", (
        f"positive control: expected ResourceNotFoundException for a fully-permissioned caller "
        f"naming a well-formed, nonexistent registry by ID, got {control_code}: {control_message!r}"
    )
    assert control_message == f"Registry not found: {missing_id}", (
        f"unexpected ResourceNotFoundException message: {control_message!r}"
    )

    restricted = _restricted_client(ctx, "agent-registry")

    id_form_code, id_form_message = _refusal_once_credentials_settle(
        lambda: restricted.batch_get_discoverable_registry_record(
            entries=[{"registryId": missing_id, "recordIds": [record_id]}]
        )
    )
    # The ID form carries no ARN for IAM to evaluate a resource-level policy against, so the
    # service falls through to the same not-found answer the fully-permissioned caller got.
    assert id_form_code == control_code, (
        f"expected the unpermissioned caller's ID-form request to reach the same "
        f"{control_code}, got {id_form_code}: {id_form_message!r}"
    )
    assert id_form_message == control_message, (
        f"expected the unpermissioned caller's ID-form message to match the fully-permissioned "
        f"one ({control_message!r}), got {id_form_message!r}"
    )

    arn_form_code, arn_form_message = _refusal_once_credentials_settle(
        lambda: restricted.batch_get_discoverable_registry_record(
            entries=[{"registryId": missing_arn, "recordIds": [record_id]}]
        )
    )
    assert arn_form_code == "AccessDeniedException", (
        f"expected the ARN form of the identical registry to trigger resource-level "
        f"authorization and be refused, got {arn_form_code}: {arn_form_message!r}"
    )
    assert arn_form_message == "Caller is not authorized to read the requested records.", (
        f"unexpected AccessDeniedException message: {arn_form_message!r}"
    )
    assert arn_form_code != id_form_code, (
        "naming the same registry by ARN instead of ID must change the unpermissioned caller's "
        "outcome from not-found to access-denied"
    )

    malformed_code, malformed_message = _refusal_once_credentials_settle(
        lambda: restricted.batch_get_discoverable_registry_record(
            entries=[{"registryId": missing_id, "recordIds": [malformed_record_id]}]
        )
    )
    assert malformed_code == "ValidationException", (
        f"expected an unpermissioned caller to still fail shape validation on a malformed "
        f"recordId before either authorization path, got {malformed_code}: {malformed_message!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
