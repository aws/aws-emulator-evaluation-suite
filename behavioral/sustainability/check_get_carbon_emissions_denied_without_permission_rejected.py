"""get-carbon-emissions-denied-without-permission-rejected."""
from __future__ import annotations

import time
from datetime import datetime, timezone
from typing import Any

from behavioral_harness import tags

CHECK = "get-carbon-emissions-denied-without-permission-rejected"
GROUP = "overly-permissive"
SERVICES = ["sustainability"]


@tags("axis:rejection", "cap:c2", "cap:c7", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """An IAM principal with no attached permissions is rejected by
    GetEstimatedCarbonEmissions with AccessDeniedException, while the default
    (fully-permissioned) caller in the same file succeeds against the identical request."""
    iam = ctx.client("iam")
    user_name = ctx.unique_name("sim2real-behav-sustain-user-")
    iam.create_user(UserName=user_name, Tags=[{"Key": "sim2real", "Value": CHECK}])
    ctx.on_cleanup(lambda: iam.delete_user(UserName=user_name))

    key = iam.create_access_key(UserName=user_name)["AccessKey"]
    ctx.on_cleanup(lambda: iam.delete_access_key(UserName=user_name, AccessKeyId=key["AccessKeyId"]))

    start, end = _carbon_window(ctx)
    creds = {"aws_access_key_id": key["AccessKeyId"], "aws_secret_access_key": key["SecretAccessKey"]}
    restricted = _wait_for_usable_credentials(ctx, creds)

    code, message = _error(
        lambda: restricted.get_estimated_carbon_emissions(TimePeriod={"Start": start, "End": end})
    )
    assert code == "AccessDeniedException", f"expected AccessDeniedException, got {code!r}"
    action = "sustainability:GetEstimatedCarbonEmissions"
    expected = (
        f"User: arn:aws:iam::{ctx.account}:user/{user_name} is not authorized to perform: {action} "
        f"on resource: arn:aws:sustainability:us-east-1:{ctx.account}:/v1/estimated-carbon-emissions "
        f"because no identity-based policy allows the {action} action"
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Positive control: the default, fully-permissioned caller succeeds on the identical request.
    default_client = _sustainability_client(ctx)
    resp = default_client.get_estimated_carbon_emissions(TimePeriod={"Start": start, "End": end})
    results = resp["Results"]
    assert isinstance(results, list), f"expected a Results list, got {results!r}"


def _sustainability_client(ctx):
    """AWS Sustainability serves one endpoint in us-east-1, so every target is called there."""
    return ctx.client("sustainability", region="us-east-1")


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _month_floor(dt: datetime) -> datetime:
    return dt.replace(day=1, hour=0, minute=0, second=0, microsecond=0)


def _add_months(dt: datetime, n: int) -> datetime:
    total = dt.month - 1 + n
    year = dt.year + total // 12
    month = total % 12 + 1
    return dt.replace(year=year, month=month, day=1, hour=0, minute=0, second=0, microsecond=0)


def _carbon_window(ctx):
    now = _utc_now()
    end = _add_months(_month_floor(now), -3)
    start = _add_months(end, -12)
    return start, end


def _error(fn):
    """Call fn(); return its botocore Error (code, message). An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _wait_for_usable_credentials(ctx, creds: dict[str, str], timeout_s: float = 30.0) -> Any:
    """New IAM access keys take a few seconds to propagate; poll STS until the credentials
    are recognized (not InvalidClientTokenId), then return a sustainability client re-signed
    with them but still pointed at THIS run's target -- real AWS or the emulator -- via
    ctx.client()'s ``creds`` override rather than a hand-rolled boto3 client, which would carry
    no endpoint pin and always reach real AWS regardless of target."""
    from botocore.exceptions import ClientError

    sts = ctx.client("sts", creds=creds)
    deadline = time.monotonic() + timeout_s
    last_code = None
    while time.monotonic() < deadline:
        try:
            sts.get_caller_identity()
            break
        except ClientError as e:
            last_code = e.response["Error"]["Code"]
            time.sleep(1.5)
    else:
        raise AssertionError(f"new IAM credentials never became usable (last error: {last_code})")

    return ctx.client("sustainability", region="us-east-1", creds=creds)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
