"""authenticated-ingress-point-archives-the-delivered-message."""
from __future__ import annotations

import datetime
import smtplib
import socket
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "authenticated-ingress-point-archives-the-delivered-message"
GROUP = "ingress-delivery"
SERVICES = ["mailmanager"]

_PROVISION_BUDGET_S = 180.0
_DNS_BUDGET_S = 900.0
_ARCHIVE_BUDGET_S = 240.0
_GONE_BUDGET_S = 180.0
_SMTP_PORT = 587


def _teardown(undo, *not_found: str):
    """A cleanup running ``undo()`` where a failed delete raises."""

    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _teardown_and_await_gone(delete, get, *, not_found: str,
                              budget_s: float = _GONE_BUDGET_S, poll_s: float = 5.0):
    """Delete, then poll ``get`` to the resource's own not-found so a dependent delete never races it."""

    def run_undo() -> None:
        try:
            delete()
        except ClientError as exc:
            if exc.response["Error"]["Code"] != not_found:
                raise
            return
        deadline = time.monotonic() + budget_s
        while True:
            try:
                get()
            except ClientError as exc:
                if exc.response["Error"]["Code"] == not_found:
                    return
                raise
            assert time.monotonic() < deadline, f"resource still present {budget_s}s after delete"
            time.sleep(poll_s)

    return run_undo


def _wait_active(mm, ingress_point_id: str, *, budget_s: float = _PROVISION_BUDGET_S,
                  poll_s: float = 5.0) -> str:
    """Poll GetIngressPoint past PROVISIONING/UPDATING; returns the ARecord once ACTIVE."""
    deadline = time.monotonic() + budget_s
    while True:
        r = mm.get_ingress_point(IngressPointId=ingress_point_id)
        if r["Status"] not in ("PROVISIONING", "UPDATING"):
            assert r["Status"] == "ACTIVE", f"ingress point reached {r['Status']!r}, not ACTIVE"
            return r["ARecord"]
        assert time.monotonic() < deadline, f"ingress point still {r['Status']!r} after {budget_s}s"
        time.sleep(poll_s)


def _wait_dns(host: str, *, budget_s: float = _DNS_BUDGET_S, poll_s: float = 5.0) -> None:
    """Poll until the ingress endpoint's A record resolves; its DNS zone propagates after create."""
    deadline = time.monotonic() + budget_s
    while True:
        try:
            socket.gethostbyname(host)
            return
        except OSError:
            assert time.monotonic() < deadline, f"{host!r} did not resolve within {budget_s}s"
            time.sleep(poll_s)


def _deliver(host: str, username: str, password: str, sender: str, recipient: str,
             subject: str, body: str, port: int = _SMTP_PORT) -> None:
    """Submit one message over SMTP AUTH+STARTTLS, the way a trusted sender would."""
    with smtplib.SMTP(host, port, timeout=30) as smtp:
        smtp.ehlo("sim2real-behav-mm")
        smtp.starttls()
        smtp.ehlo("sim2real-behav-mm")
        smtp.login(username, password)
        message = (
            f"From: {sender}\r\n"
            f"To: {recipient}\r\n"
            f"Subject: {subject}\r\n"
            "MIME-Version: 1.0\r\n"
            "Content-Type: text/plain\r\n"
            "\r\n"
            f"{body}\r\n"
        )
        refused = smtp.sendmail(sender, [recipient], message)
        assert refused == {}, f"recipient(s) refused: {refused!r}"


def _find_by_subject(mm, archive_id: str, subject: str, *, budget_s: float = _ARCHIVE_BUDGET_S,
                      poll_s: float = 10.0) -> dict:
    """Poll StartArchiveSearch/GetArchiveSearchResults until the delivered message is indexed."""
    now = datetime.datetime.now(datetime.timezone.utc)
    deadline = time.monotonic() + budget_s
    while True:
        search_id = mm.start_archive_search(
            ArchiveId=archive_id,
            FromTimestamp=now - datetime.timedelta(minutes=10),
            ToTimestamp=now + datetime.timedelta(minutes=10),
            MaxResults=10,
            Filters={"Include": [{"StringExpression": {
                "Evaluate": {"Attribute": "SUBJECT"},
                "Operator": "CONTAINS",
                "Values": [subject],
            }}]},
        )["SearchId"]
        search_deadline = time.monotonic() + 30.0
        state = None
        while time.monotonic() < search_deadline:
            state = mm.get_archive_search(SearchId=search_id)["Status"]["State"]
            if state in ("COMPLETED", "FAILED", "CANCELLED"):
                break
            time.sleep(2.0)
        assert state == "COMPLETED", f"archive search reached {state!r}, not COMPLETED"
        rows = mm.get_archive_search_results(SearchId=search_id)["Rows"]
        if rows:
            assert len(rows) == 1, f"expected exactly one archived message, found {len(rows)}: {rows!r}"
            return rows[0]
        assert time.monotonic() < deadline, (
            f"no archived message with subject {subject!r} appeared within {budget_s}s"
        )
        time.sleep(poll_s)


@tags(
    "axis:happy-path",
    "cap:c1",
    "cap:c4",
    "concern:data-plane",
    "concern:representation",
    "dp:native",
    "plane:control",
    "plane:data",
)
def run(ctx) -> None:
    """A message submitted over SMTP to an authenticated ingress point is routed through its
    rule set into an archive, and both the archived row and the archived body read back carry
    the content that was actually sent.

    Reference: https://docs.aws.amazon.com/ses/latest/dg/eb-ingress.html
    """
    mm = ctx.client("mailmanager")

    archive_id = mm.create_archive(ArchiveName=ctx.unique_name("sim2real-behav-mm-arc-"))["ArchiveId"]
    ctx.on_cleanup(_teardown(lambda: mm.delete_archive(ArchiveId=archive_id), "ResourceNotFoundException"))

    rule_set_id = mm.create_rule_set(
        RuleSetName=ctx.unique_name("sim2real-behav-mm-rs-"),
        Rules=[{"Actions": [{"Archive": {"TargetArchive": archive_id}}]}],
    )["RuleSetId"]
    ctx.on_cleanup(_teardown(lambda: mm.delete_rule_set(RuleSetId=rule_set_id), "ResourceNotFoundException"))

    traffic_policy_id = mm.create_traffic_policy(
        TrafficPolicyName=ctx.unique_name("sim2real-behav-mm-tp-"),
        PolicyStatements=[],
        DefaultAction="ALLOW",
    )["TrafficPolicyId"]
    ctx.on_cleanup(
        _teardown(lambda: mm.delete_traffic_policy(TrafficPolicyId=traffic_policy_id),
                  "ResourceNotFoundException")
    )

    password = f"Sim2realBehav{ctx.unique_name('')}Aa1!"
    ingress_point_id = mm.create_ingress_point(
        IngressPointName=ctx.unique_name("sim2real-behav-mm-ip-"),
        Type="AUTH",
        RuleSetId=rule_set_id,
        TrafficPolicyId=traffic_policy_id,
        IngressPointConfiguration={"SmtpPassword": password},
        TlsPolicy="FIPS",
    )["IngressPointId"]
    ctx.on_cleanup(_teardown_and_await_gone(
        lambda: mm.delete_ingress_point(IngressPointId=ingress_point_id),
        lambda: mm.get_ingress_point(IngressPointId=ingress_point_id),
        not_found="ResourceNotFoundException",
    ))

    a_record, smtp_port = ctx.endpoint_host(_wait_active(mm, ingress_point_id), _SMTP_PORT)
    _wait_dns(a_record)

    subject = ctx.unique_name("sim2real-behav-mm-subj-")
    body_marker = ctx.unique_name("sim2real-behav-mm-body-")
    sender = f"{ctx.unique_name('sim2real-behav-mm-from-')}@example.test"
    recipient = f"{ctx.unique_name('sim2real-behav-mm-to-')}@example.test"

    _deliver(a_record, ingress_point_id, password, sender, recipient, subject, body_marker, smtp_port)

    row = _find_by_subject(mm, archive_id, subject)
    assert row["Subject"] == subject, f"archived row had Subject {row['Subject']!r}, expected {subject!r}"
    assert row["From"] == sender, f"archived row had From {row['From']!r}, expected {sender!r}"
    assert row["To"] == recipient, f"archived row had To {row['To']!r}, expected {recipient!r}"

    content = mm.get_archive_message_content(ArchivedMessageId=row["ArchivedMessageId"])["Body"]
    assert content["MessageMalformed"] is False, f"archived message was reported malformed: {content!r}"
    assert body_marker in content["Text"], (
        f"archived message body {content['Text']!r} did not contain the delivered marker {body_marker!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
