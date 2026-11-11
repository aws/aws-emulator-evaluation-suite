"""create-connector-missing-iam-permission-rejected."""
from __future__ import annotations

import json
import time
import uuid

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "create-connector-missing-iam-permission-rejected"
GROUP = "overly-permissive"
SERVICES = ["pca-connector-ad"]


@tags("axis:rejection", "cap:c7", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A role with an explicit Deny on pca-connector-ad:CreateConnector gets AccessDeniedException with
    its exact message, while the caller's own call gets the exact DirectoryRegistration
    ResourceNotFoundException; ListConnectors shows no connector from either call."""
    iam = ctx.client("iam")
    sts = ctx.client("sts")
    account = sts.get_caller_identity()["Account"]
    role_name = ctx.unique_name("sim2real-pcad-deny-")

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
        Tags=[{"Key": "sim2real", "Value": "pca-connector-ad"}],
    )
    ctx.on_cleanup(lambda: _safe(lambda: iam.delete_role(RoleName=role_name)))

    # the Allow lets every other authorization (TagResource for the request's Tags) pass, so
    # the explicit Deny on CreateConnector is what refuses the call.
    deny_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Action": "pca-connector-ad:*", "Resource": "*"},
            {"Effect": "Deny", "Action": "pca-connector-ad:CreateConnector", "Resource": "*"},
        ],
    }
    iam.put_role_policy(
        RoleName=role_name, PolicyName="deny-create-connector", PolicyDocument=json.dumps(deny_policy)
    )
    ctx.on_cleanup(
        lambda: _safe(
            lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="deny-create-connector")
        )
    )

    role_arn = f"arn:aws:iam::{account}:role/{role_name}"
    session_name = ctx.unique_name("sess-")
    creds = _assume_role_with_retry(sts, role_arn, session_name)

    pcad = ctx.client("pca-connector-ad")
    restricted_client = ctx.client(
        "pca-connector-ad",
        creds={
            "aws_access_key_id": creds["AccessKeyId"],
            "aws_secret_access_key": creds["SecretAccessKey"],
            "aws_session_token": creds["SessionToken"],
        },
    )

    ca_arn = (
        f"arn:aws:acm-pca:{ctx.region}:{account}:certificate-authority/{uuid.uuid4()}"
    )
    kwargs = dict(
        DirectoryId="d-1234567890",
        CertificateAuthorityArn=ca_arn,
        VpcInformation={"SecurityGroupIds": ["sg-0123456789abcdef0"]},
        Tags={"sim2real": "pca-connector-ad"},
    )

    expected_denial = (
        f"User: arn:aws:sts::{account}:assumed-role/{role_name}/{session_name} is not "
        "authorized to perform: pca-connector-ad:CreateConnector on resource: "
        f"arn:aws:pca-connector-ad:{ctx.region}:{account}:connector/* with an explicit deny "
        "in an identity-based policy"
    )
    # IAM propagation: the role's inline policy reaches the authorizer eventually; retry the
    # call, bounded, until the explicit Deny is the one answering.
    deadline = time.monotonic() + 60
    while True:
        code, message = _error(lambda: restricted_client.create_connector(**kwargs))
        if message == expected_denial or time.monotonic() > deadline:
            break
        time.sleep(3)
    assert code == "AccessDeniedException", f"expected AccessDeniedException, got {code!r}"
    assert message == expected_denial, message

    # effect absent: an independent read (a different operation than the mutating call, at
    # the destination) proves no connector was created for the denied attempt. ca_arn is
    # unique to this run, so this is exact even with other checks running concurrently.
    denied_matches = [
        c for c in pcad.list_connectors()["Connectors"] if c["CertificateAuthorityArn"] == ca_arn
    ]
    assert denied_matches == [], f"denied attempt must create no connector, found: {denied_matches}"

    # positive control: the identical call under full permissions clears the authorization
    # gate and is refused for the unregistered directory instead.
    control_code, control_message = _error(lambda: pcad.create_connector(**kwargs))
    assert control_code == "ResourceNotFoundException", (
        f"positive control must clear the authorization gate, got {control_code!r}"
    )
    assert control_message == "DirectoryRegistration was not found: d-1234567890.", (
        control_message
    )

    # terminal read: independent of both calls above, the refused control left no connector.
    control_matches = [
        c for c in pcad.list_connectors()["Connectors"] if c["CertificateAuthorityArn"] == ca_arn
    ]
    assert control_matches == [], (
        f"positive control failed but still left a connector behind: {control_matches}"
    )


def _safe(fn) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _assume_role_with_retry(sts, role_arn: str, session_name: str, attempts: int = 8) -> dict:
    # IAM role/policy propagation is eventually consistent; poll AssumeRole until it works.
    last_exc: Exception | None = None
    for _ in range(attempts):
        try:
            return sts.assume_role(RoleArn=role_arn, RoleSessionName=session_name)["Credentials"]
        except Exception as exc:  # noqa: BLE001
            last_exc = exc
            time.sleep(3)
    raise AssertionError(f"could not assume role after retries: {last_exc}")


def _error(fn):
    """Call fn(); return its error (code, message). A success raises, because a target that
    accepts what AWS refuses must not read as a code mismatch."""
    try:
        result = fn()
    except Exception as exc:  # noqa: BLE001
        resp = getattr(exc, "response", None)
        if resp:
            err = resp.get("Error", {})
            return err.get("Code"), err.get("Message")
        return type(exc).__name__, str(exc)
    raise AssertionError(f"expected a rejection, but the call succeeded: {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
