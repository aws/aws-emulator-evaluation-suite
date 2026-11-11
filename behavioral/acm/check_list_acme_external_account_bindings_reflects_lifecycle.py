"""list-acme-external-account-bindings-reflects-lifecycle."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-acme-external-account-bindings-reflects-lifecycle"
GROUP = "state-machine"
SERVICES = ["acm"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListAcmeExternalAccountBindings lists a new binding after creation and drops it after
    deletion, while a sibling binding on the same endpoint stays listed."""
    acm = ctx.client("acm")
    iam = ctx.client("iam")
    sts = ctx.client("sts")

    endpoint_arn = _create_active_endpoint(ctx, acm)
    role_arn_a = _create_eab_role(ctx, iam, "a")
    role_arn_b = _create_eab_role(ctx, iam, "b")
    binder = _binding_client(ctx, iam, sts, [role_arn_a, role_arn_b])

    eab_a = _retry_create_binding(ctx, binder, endpoint_arn, role_arn_a)["ExternalAccountBinding"][
        "AcmeExternalAccountBindingArn"
    ]
    ctx.on_cleanup(
        lambda: _delete_if_present(lambda: acm.delete_acme_external_account_binding(AcmeExternalAccountBindingArn=eab_a))
    )

    eab_b = _retry_create_binding(ctx, binder, endpoint_arn, role_arn_b)["ExternalAccountBinding"][
        "AcmeExternalAccountBindingArn"
    ]
    ctx.on_cleanup(
        lambda: _delete_if_present(lambda: acm.delete_acme_external_account_binding(AcmeExternalAccountBindingArn=eab_b))
    )


    arns_after_create = _list_binding_arns(acm, endpoint_arn)
    assert eab_a in arns_after_create, "binding A missing from list right after creation"
    assert eab_b in arns_after_create, "binding B missing from list right after creation"

    acm.delete_acme_external_account_binding(AcmeExternalAccountBindingArn=eab_a)

    arns_after_delete = _poll_until_absent(acm, endpoint_arn, eab_a)
    assert eab_a not in arns_after_delete, "deleted binding A still present in list"
    assert eab_b in arns_after_delete, "unrelated sibling binding B disappeared after unrelated delete"


def _delete_if_present(fn):
    """Teardown delete: return once it succeeds or the resource is already gone, retry a
    ConflictException while a dependent resource is still being released, raise the rest."""
    deadline = time.monotonic() + 30
    while True:
        try:
            fn()
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code in ("ResourceNotFoundException", "NoSuchEntity"):
                return
            if code != "ConflictException" or time.monotonic() > deadline:
                raise
            time.sleep(2)


def _create_active_endpoint(ctx, acm, contact: str | None = None) -> str:
    name = ctx.unique_name("sim2real-acme-eab-lifecycle-")
    kwargs = {
        "AuthorizationBehavior": "PRE_APPROVED",
        "CertificateAuthority": {"PublicCertificateAuthority": {}},
        "Tags": [{"Key": "Name", "Value": name}],
    }
    if contact:
        kwargs["Contact"] = contact
    arn = acm.create_acme_endpoint(**kwargs)["AcmeEndpointArn"]
    ctx.on_cleanup(lambda: _delete_if_present(lambda: acm.delete_acme_endpoint(AcmeEndpointArn=arn)))
    status = _wait_for_endpoint_status(acm, arn, {"ACTIVE", "FAILED"})
    if status != "ACTIVE":
        raise AssertionError(f"endpoint entered {status} instead of ACTIVE")
    return arn


def _wait_for_endpoint_status(acm, arn: str, target_statuses: set, timeout_s: float = 90.0, interval_s: float = 3.0) -> str:
    deadline = time.monotonic() + timeout_s
    last_status = None
    while time.monotonic() < deadline:
        last_status = acm.describe_acme_endpoint(AcmeEndpointArn=arn)["AcmeEndpoint"]["Status"]
        if last_status in target_statuses:
            return last_status
        time.sleep(interval_s)
    raise AssertionError(f"endpoint {arn} never reached {target_statuses}, last status={last_status}")


def _create_eab_role(ctx, iam, suffix: str) -> str:
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "acm-acme.amazonaws.com"},
                "Action": ["sts:AssumeRole", "sts:TagSession", "sts:SetSourceIdentity"],
                "Condition": {"StringLikeIfExists": {"sts:SourceIdentity": "acm-acme-*"}},
            }
        ],
    }
    role_name = ctx.unique_name(f"sim2real-acme-eab-role-{suffix}-")
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "Name", "Value": role_name}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: _delete_if_present(lambda: iam.delete_role(RoleName=role_name)))
    return role_arn


def _binding_client(ctx, iam, sts, role_arns):
    # CreateAcmeExternalAccountBinding needs iam:PassRole on each binding role; a role the check
    # creates holds only that grant and the create call, so the calling identity's own policies
    # stay untouched.
    identity = sts.get_caller_identity()
    name = ctx.unique_name("sim2real-acme-eab-binder-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{identity['Account']}:root"},
                "Action": "sts:AssumeRole",
                "Condition": {"StringEquals": {"aws:userid": identity["UserId"]}},
            }
        ],
    }
    binder_arn = iam.create_role(RoleName=name, AssumeRolePolicyDocument=json.dumps(trust_policy))["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    policy_doc = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "iam:PassRole",
                "Resource": list(role_arns),
            },
            {"Effect": "Allow", "Action": "acm:CreateAcmeExternalAccountBinding", "Resource": "*"},
        ],
    }
    iam.put_role_policy(RoleName=name, PolicyName="acme-eab-binder", PolicyDocument=json.dumps(policy_doc))
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=name, PolicyName="acme-eab-binder"))
    # A new role's trust policy propagates with a lag; retry only the documented denial.
    deadline = time.monotonic() + min(60.0, ctx.time_left() or 60.0)
    while True:
        try:
            creds = sts.assume_role(RoleArn=binder_arn, RoleSessionName="acme-eab-binder")["Credentials"]
            break
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "AccessDenied" or time.monotonic() >= deadline:
                raise
            time.sleep(2.0)
    return ctx.client(
        "acm",
        creds={
            "aws_access_key_id": creds["AccessKeyId"],
            "aws_secret_access_key": creds["SecretAccessKey"],
            "aws_session_token": creds["SessionToken"],
        },
    )


def _retry_create_binding(
    ctx, acm, endpoint_arn: str, role_arn: str, timeout_s: float = 180.0, interval_s: float = 2.0
) -> dict:
    """IAM grants and a fresh role session propagate with a lag; retry past AccessDeniedException
    and UnrecognizedClientException until the binder role's session and PassRole permission are
    visible to the ACM control plane."""
    deadline = time.monotonic() + min(timeout_s, ctx.time_left() or timeout_s)
    last_exc: ClientError | None = None
    while time.monotonic() < deadline:
        try:
            return acm.create_acme_external_account_binding(AcmeEndpointArn=endpoint_arn, RoleArn=role_arn)
        except ClientError as exc:
            if exc.response["Error"]["Code"] not in ("AccessDeniedException", "UnrecognizedClientException"):
                raise
            last_exc = exc
            time.sleep(interval_s)
    raise AssertionError(f"CreateAcmeExternalAccountBinding still denied after {timeout_s}s: {last_exc}")


def _list_binding_arns(acm, endpoint_arn: str) -> set[str]:
    arns: set[str] = set()
    token = None
    while True:
        kwargs = {"AcmeEndpointArn": endpoint_arn}
        if token:
            kwargs["NextToken"] = token
        resp = acm.list_acme_external_account_bindings(**kwargs)
        arns.update(b["AcmeExternalAccountBindingArn"] for b in resp.get("ExternalAccountBindings", []))
        token = resp.get("NextToken")
        if not token:
            return arns


def _poll_until_absent(acm, endpoint_arn: str, missing_arn: str, timeout_s: float = 60.0, interval_s: float = 2.0) -> set[str]:
    deadline = time.monotonic() + timeout_s
    arns: set[str] = set()
    while time.monotonic() < deadline:
        arns = _list_binding_arns(acm, endpoint_arn)
        if missing_arn not in arns:
            return arns
        time.sleep(interval_s)
    raise AssertionError(f"{missing_arn} still present in list after deletion: {arns}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
