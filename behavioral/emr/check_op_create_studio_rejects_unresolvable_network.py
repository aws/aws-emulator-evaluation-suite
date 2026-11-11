"""op-create-studio-rejects-unresolvable-network."""
from __future__ import annotations

import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

def _unique_name(prefix=""):
    return f"sim2real-behav-{prefix}{uuid.uuid4().hex[:8]}"


def _error(fn):
    """Call fn(); return its error (code, message). An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(
        f"expected CreateStudio to reject a bad network/role request, but it "
        f"SUCCEEDED and returned {result!r}"
    )


def _account_id(ctx):
    return ctx.client("sts").get_caller_identity()["Account"]


def _role_arn(ctx, role_name):
    return f"arn:aws:iam::{_account_id(ctx)}:role/{role_name}"

CHECK = "op-create-studio-rejects-unresolvable-network"
GROUP = 'overly-permissive'
SERVICES = ['emr']

def _service_message(text, message, service="AWSEditors"):
    """`text` as the EMR backend `service` words a refusal; only its per-call request id is taken
    from the actual message."""
    request_id = (message or "").rsplit("Request ID: ", 1)[-1].split(";", 1)[0]
    return (
        f"{text} (Service: {service}; Status Code: 400; Error Code: InvalidRequestException; "
        f"Request ID: {request_id}; Proxy: null)"
    )


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateStudio with an unresolvable network and a service role that does not exist fails with
    InvalidRequestException and AWS's exact cannot-assume-role message, and leaves no studio behind."""
    emr = ctx.client("emr")
    name = _unique_name("emr-studio-")

    role_arn = _role_arn(ctx, _unique_name("emr-missing-role-"))
    code, message = _error(
        lambda: emr.create_studio(
            Name=name,
            AuthMode="IAM",
            VpcId="vpc-0fedcba987654321f",
            SubnetIds=["subnet-0fedcba987654321f"],
            ServiceRole=role_arn,
            WorkspaceSecurityGroupId="sg-0fedcba987654321a",
            EngineSecurityGroupId="sg-0fedcba987654321b",
            DefaultS3Location=f"s3://{_unique_name('emr-studio-bucket-')}/",
        )
    )
    assert code == "InvalidRequestException", (
        f"expected CreateStudio to reject a bad network/role request with InvalidRequestException, got {code}"
    )
    expected = _service_message(f"This entity does not have permissions to assume role '{role_arn}'", message)
    assert message == expected, f"expected the message {expected!r}, got {message!r}"

    # No partially created studio may be observable afterwards.
    names = []
    marker = None
    for _ in range(50):
        kwargs = {"Marker": marker} if marker else {}
        resp = emr.list_studios(**kwargs)
        names.extend(s["Name"] for s in resp.get("Studios", []))
        marker = resp.get("Marker")
        if not marker:
            break
    else:
        raise AssertionError("ListStudios did not terminate in 50 pages")
    assert name not in names, "a rejected CreateStudio must not leave a studio behind"

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
