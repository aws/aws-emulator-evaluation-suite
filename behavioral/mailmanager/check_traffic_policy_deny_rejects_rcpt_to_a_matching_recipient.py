"""traffic-policy-deny-rejects-rcpt-to-a-matching-recipient."""
from __future__ import annotations

import smtplib
import socket
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "traffic-policy-deny-rejects-rcpt-to-a-matching-recipient"
GROUP = "ingress-delivery"
SERVICES = ["mailmanager"]

_PROVISION_BUDGET_S = 180.0
_DNS_BUDGET_S = 900.0
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


def _rcpt(host: str, username: str, password: str, sender: str, recipient: str,
          port: int = _SMTP_PORT) -> tuple[int, bytes]:
    """The SMTP response to one RCPT TO, issued after a fresh AUTH session for that recipient."""
    with smtplib.SMTP(host, port, timeout=30) as smtp:
        smtp.ehlo("sim2real-behav-mm")
        smtp.starttls()
        smtp.ehlo("sim2real-behav-mm")
        smtp.login(username, password)
        smtp.mail(sender)
        return smtp.rcpt(recipient)


@tags(
    "axis:rejection",
    "cap:c7",
    "concern:data-plane",
    "concern:negative-classes",
    "dp:native",
    "plane:control",
    "plane:data",
)
def run(ctx) -> None:
    """A traffic policy statement that denies a recipient attribute match rejects RCPT TO for a
    matching address with an exact SMTP 550 response, while a non-matching recipient in the
    same SMTP transaction type is still accepted under the policy's default-allow action.

    Reference: https://docs.aws.amazon.com/ses/latest/dg/eb-create-traffic-policy.html
    """
    mm = ctx.client("mailmanager")

    rule_set_id = mm.create_rule_set(
        RuleSetName=ctx.unique_name("sim2real-behav-mm-rs-"),
        Rules=[{"Actions": [{"Drop": {}}]}],
    )["RuleSetId"]
    ctx.on_cleanup(_teardown(lambda: mm.delete_rule_set(RuleSetId=rule_set_id), "ResourceNotFoundException"))

    blocked_token = ctx.unique_name("sim2realblocked")
    traffic_policy_id = mm.create_traffic_policy(
        TrafficPolicyName=ctx.unique_name("sim2real-behav-mm-tp-"),
        PolicyStatements=[{
            "Conditions": [{"StringExpression": {
                "Evaluate": {"Attribute": "RECIPIENT"},
                "Operator": "CONTAINS",
                "Values": [blocked_token],
            }}],
            "Action": "DENY",
        }],
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

    sender = f"{ctx.unique_name('sim2real-behav-mm-from-')}@example.test"
    denied_recipient = f"{blocked_token}@example.test"
    allowed_recipient = f"{ctx.unique_name('sim2real-behav-mm-allow-')}@example.test"

    denied_code, denied_resp = _rcpt(a_record, ingress_point_id, password, sender, denied_recipient, smtp_port)
    assert denied_code == 550, f"RCPT TO the denied recipient got {denied_code} {denied_resp!r}, expected 550"
    assert denied_resp == b"5.7.1 Delivery not authorized, message refused", (
        f"RCPT TO the denied recipient got message {denied_resp!r}, expected the documented refusal"
    )

    allowed_code, allowed_resp = _rcpt(a_record, ingress_point_id, password, sender, allowed_recipient, smtp_port)
    assert allowed_code == 250, (
        f"the positive control's RCPT TO got {allowed_code} {allowed_resp!r}, expected 250 Ok"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
