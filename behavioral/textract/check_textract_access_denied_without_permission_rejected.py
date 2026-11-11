"""textract-access-denied-without-permission-rejected."""
from __future__ import annotations

import io
import json
import time

from behavioral_harness import tags

CHECK = "textract-access-denied-without-permission-rejected"
GROUP = "overly-permissive"
SERVICES = ["textract"]
_SESSION_NAME = "sim2real-noperm-session"


@tags("axis:rejection", "cap:c7", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A role with no textract permissions at all is denied (implicit deny) with
    AccessDeniedException when it calls DetectDocumentText, while the harness's own credentials
    (positive control) succeed on the identical call."""
    iam = ctx.client("iam")
    sts = ctx.client("sts")
    account_id = ctx.account

    role_name = ctx.unique_name("sim2real-textract-noperm-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real", "Value": "textract-access-denied-without-permission-rejected"}],
    )
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    role_arn = f"arn:aws:iam::{account_id}:role/{role_name}"

    creds = _assume_role_with_retry(sts, role_arn)

    base_textract = ctx.client("textract")
    denied_client = ctx.client(
        "textract",
        creds={
            "aws_access_key_id": creds["AccessKeyId"],
            "aws_secret_access_key": creds["SecretAccessKey"],
            "aws_session_token": creds["SessionToken"],
        },
    )

    png_bytes = _tiny_png()
    err = _client_error(lambda: denied_client.detect_document_text(Document={"Bytes": png_bytes}))
    assert err["Code"] == "AccessDeniedException", (
        f"a role with no textract permissions at all must be denied with AccessDeniedException "
        f"on DetectDocumentText; got {err['Code']!r}"
    )
    expected_message = (
        f"User: arn:aws:sts::{account_id}:assumed-role/{role_name}/{_SESSION_NAME} is not "
        f"authorized to perform: textract:DetectDocumentText because no identity-based policy "
        f"allows the textract:DetectDocumentText action"
    )
    assert err.get("Message") == expected_message, (
        f"expected message {expected_message!r}, got {err.get('Message')!r}"
    )

    # Positive control: the harness's own (permitted) credentials succeed on the same document.
    resp = base_textract.detect_document_text(Document={"Bytes": png_bytes})
    assert "Blocks" in resp, (
        f"the identical DetectDocumentText call from a permitted principal must succeed and "
        f"return Blocks, isolating the denial above as an IAM-authorization effect; got keys "
        f"{sorted(resp.keys())!r}"
    )


def _client_error(fn):
    """Call fn(); return the botocore Error dict (Code and Message). An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


def _assume_role_with_retry(sts, role_arn: str, timeout_s: float = 60.0, interval_s: float = 3.0):
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            resp = sts.assume_role(RoleArn=role_arn, RoleSessionName=_SESSION_NAME)
            return resp["Credentials"]
        except ClientError as exc:
            last_exc = exc
            time.sleep(interval_s)
    raise AssertionError(f"could not assume freshly created role within {timeout_s}s: {last_exc}")


def _tiny_png() -> bytes:
    from PIL import Image

    img = Image.new("RGB", (200, 100), "white")
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
