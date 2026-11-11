"""search-discoverable-registry-records-unauthorized."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "search-discoverable-registry-records-unauthorized"
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
    returned as a `service` client signing with those temporary credentials: any control-plane
    call through it is guaranteed to be rejected for lack of permission."""
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
    principal = f"arn:aws:sts::{account_id}:assumed-role/{role_name}/{session_name}"
    return ctx.client(service, creds=cred_kwargs), principal


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
    """SearchDiscoverableRegistryRecords refuses an unpermissioned caller before it ever checks
    whether the registry it searches exists, and names the same canonical registry ARN whether
    the caller addressed the registry by its plain ID or by its full ARN.
    """
    ar = ctx.client("agent-registry")
    account_id = ctx.account
    region = ctx.region
    missing_id = "sim2realnotfnd1"
    missing_arn = f"arn:aws:agent-registry:{region}:{account_id}:registry/{missing_id}"
    malformed_id = "bad id!"
    query = "smoke-test"

    not_found_code, not_found_message = _error(
        lambda: ar.search_discoverable_registry_records(searchQuery=query, registryIds=[missing_id])
    )
    assert not_found_code == "ResourceNotFoundException", (
        f"positive control: expected ResourceNotFoundException for a well-formed, nonexistent "
        f"registry, got {not_found_code}: {not_found_message!r}"
    )
    assert not_found_message == f"Registry not found: {missing_id}", (
        f"unexpected ResourceNotFoundException message: {not_found_message!r}"
    )

    malformed_code, malformed_message = _error(
        lambda: ar.search_discoverable_registry_records(searchQuery=query, registryIds=[malformed_id])
    )
    assert malformed_code == "ValidationException", (
        f"positive control: expected ValidationException for a malformed registryId, got "
        f"{malformed_code}: {malformed_message!r}"
    )

    restricted, principal = _restricted_client(ctx, "agent-registry")

    denied_code, denied_message = _refusal_once_credentials_settle(
        lambda: restricted.search_discoverable_registry_records(
            searchQuery=query, registryIds=[missing_id]
        )
    )
    assert denied_code == "AccessDeniedException", (
        f"expected AccessDeniedException for an unpermissioned caller naming a REAL (if "
        f"nonexistent) registry by ID, got {denied_code}: {denied_message!r}"
    )
    expected_denied = (
        f"User: {principal} is not authorized to perform: "
        f"agent-registry:SearchDiscoverableRegistryRecords on resource: {missing_arn} "
        "because no identity-based policy allows the agent-registry:SearchDiscoverableRegistryRecords "
        "action"
    )
    assert denied_message == expected_denied, (
        f"expected the no-allow message {expected_denied!r}, got {denied_message!r}"
    )
    assert denied_code != not_found_code, (
        "the no-permission and missing-registry refusals must be distinct codes"
    )

    denied_arn_code, denied_arn_message = _refusal_once_credentials_settle(
        lambda: restricted.search_discoverable_registry_records(
            searchQuery=query, registryIds=[missing_arn]
        )
    )
    assert denied_arn_code == "AccessDeniedException", (
        f"expected AccessDeniedException addressing the same registry by ARN, got "
        f"{denied_arn_code}: {denied_arn_message!r}"
    )
    assert denied_arn_message == denied_message, (
        f"addressing the registry by ARN instead of ID produced a different denial "
        f"({denied_arn_message!r}) than by ID ({denied_message!r}); the authorization context "
        f"should normalize to the same resource"
    )

    malformed_denied_code, malformed_denied_message = _refusal_once_credentials_settle(
        lambda: restricted.search_discoverable_registry_records(
            searchQuery=query, registryIds=[malformed_id]
        )
    )
    assert malformed_denied_code == "ValidationException", (
        f"expected an unpermissioned caller to still fail shape validation before authorization, "
        f"got {malformed_denied_code}: {malformed_denied_message!r}"
    )
    assert malformed_denied_message == malformed_message, (
        f"an unpermissioned caller saw a different validation message ({malformed_denied_message!r}) "
        f"than the fully-permissioned one ({malformed_message!r})"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
