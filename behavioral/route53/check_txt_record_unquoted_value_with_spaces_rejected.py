"""txt-record-unquoted-value-with-spaces-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "txt-record-unquoted-value-with-spaces-rejected"
GROUP = "validation"
SERVICES = ["route53"]


def _error(fn) -> tuple[str, str]:
    """(Error.Code, Error.Message) that ``fn`` raises. An unexpected success raises too."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err.get("Code", ""), err.get("Message", "")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """An unquoted TXT value with spaces is refused with InvalidChangeBatch and the exact message,
    writes nothing, and the same value in quotes is stored and lists back byte-identical.
    """
    route53 = ctx.client("route53")
    zone_name = f"{ctx.unique_name('sim2real-txtq-')}.com."
    zone = route53.create_hosted_zone(Name=zone_name, CallerReference=ctx.unique_name("caller-"))
    zone_id = zone["HostedZone"]["Id"]
    ctx.on_cleanup(lambda: _safe_delete_zone(ctx, zone_id))
    route53.change_tags_for_resource(
        ResourceType="hostedzone", ResourceId=zone_id.split("/")[-1],
        AddTags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    _poll_change_insync(ctx, zone["ChangeInfo"]["Id"])

    record = f"spf.{zone_name}"
    raw = "v=spf1 include:example.net ~all"
    code, message = _error(lambda: _change(route53, zone_id, "CREATE", record, raw))
    assert code == "InvalidChangeBatch", f"an unquoted TXT value with spaces returned {code!r}: {message!r}"
    expected = (
        f"[Invalid Resource Record: 'FATAL problem: InvalidCharacterString "
        f"(Value should be enclosed in quotation marks) encountered with '{raw}'']"
    )
    assert message == expected, f"refusal message was {message!r}, expected {expected!r}"
    assert _txt_values(route53, zone_id, record) is None, "the refused CREATE left a TXT record under the name"

    quoted = f'"{raw}"'
    change = _change(route53, zone_id, "CREATE", record, quoted)
    ctx.on_cleanup(lambda: _change(route53, zone_id, "DELETE", record, quoted))
    _poll_change_insync(ctx, change["ChangeInfo"]["Id"])
    values = _txt_values(route53, zone_id, record)
    assert values == [quoted], f"the quoted TXT value lists back as {values!r}, expected {[quoted]!r}"


def _change(route53, zone_id: str, action: str, name: str, value: str) -> dict:
    return route53.change_resource_record_sets(
        HostedZoneId=zone_id,
        ChangeBatch={
            "Changes": [
                {
                    "Action": action,
                    "ResourceRecordSet": {
                        "Name": name, "Type": "TXT", "TTL": 300, "ResourceRecords": [{"Value": value}],
                    },
                }
            ]
        },
    )


def _txt_values(route53, zone_id: str, name: str):
    """The TXT values stored under ``name``, or None when there is no such record set."""
    resp = route53.list_resource_record_sets(
        HostedZoneId=zone_id, StartRecordName=name, StartRecordType="TXT", MaxItems="1"
    )
    for rr in resp["ResourceRecordSets"]:
        if rr["Name"] == name and rr["Type"] == "TXT":
            return [r["Value"] for r in rr["ResourceRecords"]]
    return None


def _poll_change_insync(ctx, change_id: str, timeout_s: float = 120.0) -> None:
    route53 = ctx.client("route53")
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        status = route53.get_change(Id=change_id)["ChangeInfo"]["Status"]
        if status == "INSYNC":
            return
        time.sleep(3)
    raise AssertionError(f"change never reached INSYNC within {timeout_s:.0f}s; last status {status!r}")


def _safe_delete_zone(ctx, zone_id: str) -> None:
    try:
        ctx.client("route53").delete_hosted_zone(Id=zone_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchHostedZone":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
