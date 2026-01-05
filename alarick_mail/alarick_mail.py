import asyncio
import ssl
import tomllib
import os
import bcrypt
import dns.asyncresolver
import aiosmtplib
from aiosmtpd.controller import Controller
from aiosmtpd.smtp import AuthResult, LoginPassword
from sqlalchemy import create_engine, text
#import logging


async def get_mx(domain):
    try:
        records = await dns.asyncresolver.resolve(domain, "MX")
        return (i.exchange.to_text().rstrip(".") for i in sorted(records, key=lambda r: r.preference))
    except dns.resolver.NoAnswer:
        return (domain, )
    except:
        return None


class IncomingHandler:
     async def handle_RCPT(self, server, session, envelope, address, rcpt_options):
         if not address.endswith('@example.com'):
             return '550 not relaying to that domain'
         envelope.rcpt_tos.append(address)
         return '250 OK'

     async def handle_DATA(self, server, session, envelope):
         print('Message from %s' % envelope.mail_from)
         print('Message for %s' % envelope.rcpt_tos)
         print('Message data:\n')
         for ln in envelope.content.decode('utf8', errors='replace').splitlines():
             print(f'> {ln}'.strip())
         print()
         print('End of message')
         return '250 Message accepted for delivery'


class Authenticator:
    def __init__(self, db):
        self.db = db

    def __call__(self, server, session, envelope, mechanism, auth_data):
        fail = AuthResult(success=False, handled=True, message="failllllll")
        if mechanism not in ("LOGIN", "PLAIN"):
            return AuthResult(success=False, handled=False)
        if not isinstance(auth_data, LoginPassword):
            return fail
        username = auth_data.login.decode("utf-8")
        password = auth_data.password
        with self.db.connect() as con:
            hashed = con.execute(text("SELECT password FROM virtual_users WHERE username = :username"), {"username": username}).first()
        if not hashed:
            return fail
        if not bcrypt.checkpw(password, hashed[0].encode("utf-8")):
            return fail
        return AuthResult(success=True)


class RelayHandler:
    async def handle_DATA(self, server, session, envelope):
        print("session.authenticated:", getattr(session, "authenticated", None))
        print("session.username:", getattr(session, "username", None))
        domains = {}
        for rcpt in envelope.rcpt_tos:
            _, _, domain = rcpt.partition("@")
            domains.setdefault(domain, []).append(rcpt)

        for domain, rcpts in domains.items():
            hosts = await get_mx(domain)
            for host in hosts:
                delivered = False
                try:
                    await aiosmtplib.send(
                        envelope.original_content,
                        hostname=host,
                        port=25,
                        sender=envelope.mail_from,
                        recipients=rcpts,
                        timeout=10
                    )
                    print("success")
                except:
                    continue
                else:
                    delivered = True
                    break
            if not delivered:
                print("fail")
                pass
        return "250 Message accepted for delivery"


def load_config():
    if os.path.isfile("/etc/alarick_mail/alarick_mail.conf"):
        with open("/etc/alarick_mail/alarick_mail.conf", "rb") as f:
            try:
                config = tomllib.load(f)
            except Exception:
                pass
    else:
        with open("default.conf", "rb") as f:
            config = tomllib.load(f)
    return config


async def main():
    config = load_config()
    incoming = Controller(
        IncomingHandler(),
        hostname=config.get("smtp", {}).get("incoming", {}).get("bind", "0.0.0.0"),
        port=config.get("smtp", {}).get("incoming", {}).get("port", 25)
    )
    db = create_engine(config.get("auth_db", {}).get("url", "sqlite:////var/lib/alarick_mail/auth.db"))
    ssl_ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    ssl_ctx.load_cert_chain(certfile="fullchain.pem", keyfile="privkey.pem")
    if config.get("smtp", {}).get("submission", {}).get("use_tls", False):
        tls_ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        key = config.get("smtp", {}).get("submission", {})
        if "cert_file" in key and "key_file" in key:
            tls_ctx.load_cert_chain(certfile=key.get("cert_file"), keyfile=key.get("key_file"))
            tls = {"tls_context": tls_ctx, "require_starttls": True}
        else:
            tls = {"auth_require_tls": False}
    else:
        tls = {"auth_require_tls": False}
    submission = Controller(
        RelayHandler(),
        hostname=config.get("smtp", {}).get("submission", {}).get("bind", "0.0.0.0"),
        port=config.get("smtp", {}).get("submission", {}).get("port", 587),
        authenticator=Authenticator(db),
        auth_required=True,
        **tls
    )
    try:
        incoming.start()
        submission.start()
        await asyncio.Event().wait()
    finally:
        incoming.stop()
        submission.stop()
        await db.disconnect()


if __name__ == '__main__':
    #logging.basicConfig(level=logging.DEBUG)
    asyncio.run(main())