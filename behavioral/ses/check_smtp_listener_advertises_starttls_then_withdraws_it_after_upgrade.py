"""smtp-listener-advertises-starttls-then-withdraws-it-after-upgrade."""
from __future__ import annotations

import smtplib

from behavioral_harness import tags

CHECK = "smtp-listener-advertises-starttls-then-withdraws-it-after-upgrade"
GROUP = "smtp-data-plane"
SERVICES = ["ses"]

_SMTP_PORT = 587


def _smtp_host(region: str) -> str:
    """SES's native submission endpoint for a region. Never a literal: ctx.region decides."""
    return f"email-smtp.{region}.amazonaws.com"


def _quietly_close(session: smtplib.SMTP) -> None:
    try:
        session.quit()
    except (smtplib.SMTPException, OSError):
        try:
            session.close()
        except OSError:
            pass


@tags(
    "axis:happy-path",
    "cap:c6",
    "concern:data-plane",
    "concern:representation",
    "dp:native",
    "plane:data",
)
def run(ctx) -> None:
    """The SES SMTP listener on 587 advertises STARTTLS, AUTH PLAIN LOGIN and 8BITMIME on the plaintext
    session; after a TLS 1.2+ upgrade it advertises the same set without STARTTLS, and the upgraded
    session still answers 250."""
    host, port = ctx.service_host(_smtp_host(ctx.region), _SMTP_PORT)

    session = smtplib.SMTP(host, port, timeout=30)
    ctx.on_cleanup(lambda: _quietly_close(session))

    code, banner = session.ehlo()
    assert code == 250, f"plaintext EHLO to {host}:{port} answered {code!r}: {banner!r}"
    plaintext = dict(session.esmtp_features)
    assert set(plaintext) == {"8bitmime", "starttls", "auth", "ok"}, (
        f"plaintext EHLO advertised {sorted(plaintext)!r}, expected exactly "
        f"['8bitmime', 'auth', 'ok', 'starttls']"
    )
    assert plaintext["auth"] == " PLAIN LOGIN", (
        f"plaintext EHLO advertised AUTH mechanisms {plaintext['auth']!r}, expected ' PLAIN LOGIN'"
    )

    code, response = session.starttls()
    assert code == 220, f"STARTTLS answered {code!r}: {response!r}, expected 220"
    negotiated = session.sock.version()
    assert negotiated in ("TLSv1.2", "TLSv1.3"), (
        f"upgraded socket negotiated {negotiated!r}; SES must not offer anything below TLSv1.2"
    )
    assert session.sock.cipher() is not None, (
        "STARTTLS returned 220 but the socket reports no cipher — the connection was never "
        "actually upgraded"
    )

    code, banner = session.ehlo()
    assert code == 250, f"post-upgrade EHLO answered {code!r}: {banner!r}"
    upgraded = dict(session.esmtp_features)
    assert "starttls" not in upgraded, (
        f"post-upgrade EHLO still advertises STARTTLS: {sorted(upgraded)!r} — the extension must "
        "be withdrawn once the session is already encrypted"
    )
    assert set(upgraded) == {"8bitmime", "auth", "ok"}, (
        f"post-upgrade EHLO advertised {sorted(upgraded)!r}, expected exactly "
        f"['8bitmime', 'auth', 'ok']"
    )
    assert upgraded["auth"] == plaintext["auth"], (
        f"AUTH mechanisms changed across the upgrade: {plaintext['auth']!r} -> "
        f"{upgraded['auth']!r}; they must survive STARTTLS unchanged"
    )

    code, response = session.noop()
    assert code == 250, (
        f"NOOP on the upgraded session answered {code!r}: {response!r} — the session must remain "
        "usable after STARTTLS, not merely negotiate and die"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
