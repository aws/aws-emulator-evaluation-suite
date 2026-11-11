"""attach_data_source_duplicate_rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "attach_data_source_duplicate_rejected"
GROUP = "data-plane"
SERVICES = ["opensearch"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """AttachDataSource to an unknown application id fails with ResourceNotFoundException and its exact
    message, while attaching the same domain to a real application settles to ATTACHED.
    """
    aos = ctx.client("opensearch")
    real_app_id = _create_application(ctx, aos)

    _name, arn = _create_domain_async(ctx, aos, "sim2real-dup1")

    bogus_app_id = ctx.unique_name("sim2real-noapp-").lower().replace("_", "")[:20]
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    code, message = _client_error(lambda: aos.attach_data_source(id=bogus_app_id, dataSourceArn=arn))
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code}"
    expected = f"Application {bogus_app_id} not found for account {account_id}"
    assert message == expected, f"missing-application message: expected {expected!r}, got {message!r}"

    # Positive control: attaching the same domain to a real application succeeds.
    aos.attach_data_source(id=real_app_id, dataSourceArn=arn)
    status = _wait_attachment_status(ctx, aos, real_app_id, arn, "ATTACHED")
    assert status == "ATTACHED", f"attachment entered {status}, not ATTACHED"
    final = _list_attachment_arns(aos, real_app_id)
    assert final == {arn}, f"positive control attach did not land: {final}"


def _client_error(fn):
    """(code, message) of the ClientError ``fn`` raises; a call that succeeds fails the check."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s, last value: {last}")


def _create_application(ctx, aos) -> str:
    raw = ctx.unique_name("sim2real-app-").lower()
    name = "".join(c for c in raw if c.isalnum() or c == "-")[:30].rstrip("-")
    if not name or not name[0].isalpha():
        name = "a" + name
    resp = aos.create_application(name=name[:30], tagList=[{"Key": "sim2real", "Value": "attach-data-source-duplicate-rejected"}])
    app_id = resp["id"]
    ctx.on_cleanup(lambda: aos.delete_application(id=app_id))
    return app_id


def _compliant_domain_name(ctx, prefix: str) -> str:
    raw = ctx.unique_name(f"{prefix}-").lower()
    cleaned = "".join(c for c in raw if c.isalnum() or c == "-")
    cleaned = cleaned[:28].rstrip("-")
    if not cleaned or not cleaned[0].isalpha():
        cleaned = "d" + cleaned
    return cleaned[:28]


def _create_domain_async(ctx, aos, prefix: str):
    """AttachDataSource requires the dataSourceArn to be a real OpenSearch domain.
    Kick off CreateDomain without blocking on activation -- callers may create
    several domains up front so they provision concurrently."""
    domain_name = _compliant_domain_name(ctx, prefix)
    resp = aos.create_domain(
        DomainName=domain_name,
        EngineVersion="OpenSearch_2.11",
        ClusterConfig={
            "InstanceType": "t3.small.search",
            "InstanceCount": 1,
            "DedicatedMasterEnabled": False,
            "ZoneAwarenessEnabled": False,
        },
        EBSOptions={"EBSEnabled": True, "VolumeType": "gp3", "VolumeSize": 10},
        TagList=[{"Key": "sim2real", "Value": "attach-data-source-duplicate-rejected"}],
    )
    domain_arn = resp["DomainStatus"]["ARN"]
    ctx.on_cleanup(lambda: aos.delete_domain(DomainName=domain_name))
    return domain_name, domain_arn


def _wait_attachment_status(ctx, aos, app_id: str, data_source_arn: str, want: str, timeout_s: float = 1800.0) -> str:
    def _status() -> str:
        return aos.describe_data_source_attachment(id=app_id, dataSourceArn=data_source_arn)["status"]

    return _poll_until(_status, lambda s: s in (want, "FAILED"), timeout_s=timeout_s, interval_s=15)


def _list_attachment_arns(aos, app_id: str) -> set:
    arns: set = set()
    next_token = None
    while True:
        kwargs = {"id": app_id}
        if next_token:
            kwargs["nextToken"] = next_token
        resp = aos.list_data_source_attachments(**kwargs)
        for attachment in resp.get("attachments", []):
            arns.add(attachment["dataSourceArn"])
        next_token = resp.get("nextToken")
        if not next_token:
            break
    return arns


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
