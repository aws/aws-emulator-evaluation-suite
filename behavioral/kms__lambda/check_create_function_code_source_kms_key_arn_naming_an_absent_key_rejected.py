"""create-function-code-source-kms-key-arn-naming-an-absent-key-rejected."""
from __future__ import annotations

import json
import time
import uuid
import zipfile
from io import BytesIO

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-function-code-source-kms-key-arn-naming-an-absent-key-rejected"
GROUP = "code-encryption"
SERVICES = ["iam", "kms", "lambda"]

_PREFIX = "sim2real-xsvc-"
_MANAGED = {"sim2real": "true", "sim2real:prefix": _PREFIX.rstrip("-")}

_TRUST = {
    "Version": "2012-10-17",
    "Statement": [{
        "Effect": "Allow",
        "Principal": {"Service": "lambda.amazonaws.com"},
        "Action": "sts:AssumeRole",
    }],
}

_HANDLER = """
def lambda_handler(event, context):
    return {'ok': True}
"""


def _name(ctx, kind: str) -> str:
    return ctx.unique_name(f"{_PREFIX}{kind}-")


def _zip_bytes(source: str) -> bytes:
    buf = BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("index.py", source)
    return buf.getvalue()


def _past_role_propagation(fn, *, timeout_s: float = 90.0):
    """Call fn(), retried on the exact InvalidParameterValueException IAM role propagation produces."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return fn()
        except ClientError as exc:
            err = exc.response.get("Error", {})
            if err.get("Code") != "InvalidParameterValueException" or time.monotonic() > deadline:
                raise
            time.sleep(3)


def _error(fn):
    """(code, message) of the ClientError fn() raises; raises itself if fn() unexpectedly succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a rejection, call succeeded instead: {result!r}")


@tags(
    "axis:rejection",
    "cap:c1",
    "concern:negative-classes",
    "plane:control",
)
def run(ctx) -> None:
    """A deployment package whose Code.SourceKMSKeyArn names a key KMS does not know is refused
    with KMS's own NotFoundException, and creating the identical function with no such key (the
    AWS-owned default) succeeds."""
    kms = ctx.client("kms")
    iam = ctx.client("iam")
    lam = ctx.client("lambda")

    role_name = _name(ctx, "codekms-role")
    role_arn = iam.create_role(
        RoleName=role_name,
        Path="/sim2real/",
        AssumeRolePolicyDocument=json.dumps(_TRUST),
        Tags=[{"Key": k, "Value": v} for k, v in _MANAGED.items()],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    probe_key = kms.create_key(
        Description=_name(ctx, "codekms-probe-key"),
        Tags=[{"TagKey": k, "TagValue": v} for k, v in _MANAGED.items()],
    )["KeyMetadata"]
    probe_arn = probe_key["Arn"]
    ctx.on_cleanup(lambda: kms.schedule_key_deletion(KeyId=probe_arn, PendingWindowInDays=7))
    # Same account, region and key shape as a real key: only the key id differs, so KMS's own
    # "unknown key" answer is isolated from any other difference a fabricated ARN could carry.
    absent_arn = probe_arn.rsplit("/", 1)[0] + "/" + str(uuid.uuid4())

    broken_fn = _name(ctx, "codekms-broken-fn")
    code, message = _error(lambda: lam.create_function(
        FunctionName=broken_fn,
        Runtime="python3.13",
        Role=role_arn,
        Handler="index.lambda_handler",
        Code={"ZipFile": _zip_bytes(_HANDLER), "SourceKMSKeyArn": absent_arn},
        Timeout=30,
        Tags=_MANAGED,
    ))
    assert code == "InvalidParameterValueException", (
        f"a deployment package encrypted under a key KMS has never heard of must be refused as an "
        f"invalid parameter carrying KMS's own refusal, got {code!r}: {message!r}"
    )
    # Lambda wraps KMS's answer verbatim, Request ID included; that id is KMS's own call id, not
    # a value this check created, so it is isolated the same way a RequestId field would be.
    prefix = (
        "Lambda can't find the KMS key. Check your KMS key settings. KMS exception: "
        f"NotFoundException KMS message: Key '{absent_arn}' does not exist (Service: AWSKMS; "
        "Status Code: 400; Error Code: NotFoundException; Request ID: "
    )
    suffix = "; Proxy: null)"
    assert message.startswith(prefix) and message.endswith(suffix), (
        f"unexpected message shape, got {message!r}, expected the fixed text around prefix "
        f"{prefix!r} and suffix {suffix!r}"
    )
    request_id = message[len(prefix):-len(suffix)]
    assert uuid.UUID(request_id), f"the isolated span {request_id!r} is not KMS's request id"

    good_fn = _name(ctx, "codekms-good-fn")
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=good_fn))
    created = _past_role_propagation(lambda: lam.create_function(
        FunctionName=good_fn,
        Runtime="python3.13",
        Role=role_arn,
        Handler="index.lambda_handler",
        Code={"ZipFile": _zip_bytes(_HANDLER)},
        Timeout=30,
        Tags=_MANAGED,
    ))
    assert created["FunctionName"] == good_fn, (
        f"the identical package with no customer key must create normally, "
        f"got FunctionName {created.get('FunctionName')!r} expected {good_fn!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
