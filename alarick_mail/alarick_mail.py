import asyncio
import ssl
import tomllib
import os
from smtplib import SMTPRecipientsRefused

import bcrypt
import dns.asyncresolver
import aiosmtplib
from aiosmtpd.controller import Controller
from aiosmtpd.smtp import AuthResult, LoginPassword
from sqlalchemy import create_engine, text
# import logging
import aiofiles
import aiofiles.os
from pathlib import Path
from uuid_extensions import uuid7
from typing import Generator, Sequence


class Queue:
    def __init__(self, directory: str):
        self.dir = Path(directory)

    async def put(self, folder: str, message: bytes, **metadata: str) -> None:
        path = self.dir / Path(folder)
        msg_id = uuid7().hex
        async with aiofiles.open(path / Path(msg_id), "wb")as f:
            await f.write(message)
        md = "\n".join(f"{key}={value}" for key, value in metadata.items())
        async with aiofiles.open(path / Path("~" + msg_id), "w") as f:
            await f.write(md)

    async def get_md(self, folder: str, uuid: str) -> Generator[dict[str, str], None, None]:
        async with aiofiles.open(self.dir / Path(folder) / Path("~" + uuid), "r") as f:
            data = await f.readlines()
        return dict({i.strip("\n").split("=")[0]: i.strip("\n").split("=")[1] for i in data})

    async def get_msg(self, folder: str, uuid: str):
        async with aiofiles.open(self.dir / Path(folder) / Path(uuid), "rb") as f:
            return f.read()

    async def list(self, folder: str) -> Generator[dict[str, dict[str, str]], None, None]:
        return {uuid: await self.get_md(folder, uuid) for uuid in await aiofiles.os.listdir(self.dir / Path(folder)) if not filename.startswith("~")}

    async def remove(self, folder: str, uuid: str) -> None:
        path = self.dir / Path(folder)
        await aiofiles.os.remove(path / Path(uuid))
        await aiofiles.os.remove(path / Path("~" + uuid))

    async def update(self, folder: str, uuid: str, **new_metadata: str) -> None:
        path = self.dir / Path(folder) / Path("~" + uuid)
        async with aiofiles.open(path, "r") as f:
            data = await f.readlines()
        md_dict = {}
        for line in data:
            key, value = line.strip("\n").split("=")
            md_dict[key] = value
        for key, value in new_metadata.items():
            md_dict[key] = value
        md = "\n".join(f"{key}={value}" for key, value in metadata.items())
        async with aiofiles.open(path, "w") as f:
            await f.write(md)

    async def move(self, from_folder: str, to_folder: str, uuid: str) -> None:
        await aiofiles.os.rename(self.dir / Path(from_folder) / Path(uuid),
                                 self.dir / Path(to_folder) / Path(uuid))
        await aiofiles.os.rename(self.dir / Path(from_folder) / Path("~" + uuid),
                                 self.dir / Path(to_folder) / Path("~" + uuid))

    async def make_folders(self, folders: Sequence[str]) -> None:
        for folder in folders:
            path = self.dir / Path(folder)
            if not await aiofiles.os.path.exists(path):
                await aiofiles.os.makedirs(path)


async def get_mx(domain: str) -> tuple[str] | None:
    try:
        records = await dns.asyncresolver.resolve(domain, "MX")
        return (i.exchange.to_text().rstrip(".") for i in sorted(records, key=lambda r: r.preference))
    except dns.resolver.NoAnswer:
        return (domain, )
    except:
        return None


class IncomingHandler:
    def __init__(self, queue: Queue):
        self.queue = queue

    async def handle_RCPT(self, server, session, envelope, address, rcpt_options):
         envelope.rcpt_tos.append(address)
         return '250 OK'

    async def handle_DATA(self, server, session, envelope):
         self.queue.put(
             folder="in", message=envelope.original_content,
             sender=envelope.mail_from,
             recipients=" ".join(envelope.rcpt_tos)
         )
         return '250 Message accepted for delivery'


class Authenticator:
    def __init__(self, db):
        self.db = db

    def __call__(self, server, session, envelope, mechanism, auth_data) -> AuthResult:
        fail = AuthResult(success=False, handled=True)
        if mechanism not in ("LOGIN", "PLAIN"):
            return AuthResult(success=False, handled=False)
        if not isinstance(auth_data, LoginPassword):
            return fail
        username = auth_data.login.decode("utf-8")
        password = auth_data.password
        with self.db.connect() as con:
            alias = con.execute(text("SELECT password FROM virtual_users WHERE username = (SELECT destination from virtual_aliases where source = :username)"), {"username": username}).first()
            hashed = con.execute(text("SELECT password FROM virtual_users WHERE username = :username"), {"username": username}).first()
        if not hashed:
            if not alias:
                return fail
            hashed = alias
        if not bcrypt.checkpw(password, hashed[0].encode("utf-8")):
            return fail
        return AuthResult(success=True)


class RelayHandler:
    def __init__(self, queue: Queue):
        self.queue = queue

    async def handle_DATA(self, server, session, envelope):
        domains = {}
        for rcpt in envelope.rcpt_tos:
            _, _, domain = rcpt.partition("@")
            domains.setdefault(domain, []).append(rcpt)

        for rcpts in domains.values():
            await self.queue.put(
                folder="out",
                message=envelope.original_content,
                sender=envelope.mail_from,
                recipients=" ".join(rcpts)
            )
        return "250 Message accepted for delivery"


def load_config() -> dict:
    if os.path.isfile("/etc/alarick_mail/alarick_mail.conf"):
        with open("/etc/alarick_mail/alarick_mail.conf", "rb") as f:
            try:
                config = tomllib.load(f)
            except Exception:
                pass
    else:
        with open("/usr/lib/alarick_mail/alarick_mail.conf", "rb") as f:
            config = tomllib.load(f)
    return config


async def relay_processor(queue: Queue, stop_event: asyncio.Event) -> None:
    while not stop_event.is_set():
        uuids = queue.list("out")


async def incoming_processor(queue: Queue, stop_event: asyncio.Event) -> None:
    while not stop_event.is_set():
        uuids = queue.list("in")


async def retry_processor(queue: Queue, stop_event: asyncio.Event) -> None:
    while not stop_event.is_set():
        for uuid, md in asyncio.run(queue.list("retry")):
            hosts = await get_mx(md["recipients"])
            if hosts is none:
                queue.remove("retry", uuid)
            else:
                retry = False
                for host in hosts:
                    smtp = aiosmtplib.SMTP(hostname=host, port=25, timeout=30)
                    try:
                        await smtp.connect()
                        if smtp.supports_extension("starttls"):
                            context = ssl.create_default_context()
                            await smtp.starttls(tls_context=context)
                        await smtp.sendmail("", md["recipients"], queue.get_md(folder="bounce", uuid=uuid))
                    except aiosmtplib.errors.SMTPResponseException as e:
                        if 400 <= e.code < 500:
                            retry = True
                    except SMTPRecipientsRefused:
                        pass
                    except (
                            aiosmtplib.errors.SMTPConnectError,
                            aiosmtplib.errors.SMTPServerDisconnected,
                            aiosmtplib.errors.SMTPTimeoutError,
                            asyncio.TimeoutError,
                            ConnectionResetError,
                            OSError
                    ) as e:
                        retry = True
                    except:
                        pass
                    else:
                        break
                    finally:
                        smtp.close()
                if retry:
                    queue.move("bounce", "retry", uuid)
                else:
                    queue.remove("bounce", uuid)
        await asyncio.sleep(60)





async def main() -> None:
    config = load_config()
    queue = Queue(config.get("smtp", {}).get("queue_dir", "/var/lib/alarick_mail/"))
    await queue.make_folders(("in", "out", "retry", "bounce"))

    smtp = config.get("smtp", {})
    if "cert_file" in smtp and "key_file" in smtp:
        tls_type = smtp.get("incoming", {}).get("tls", "none")
        if tls_type == "none":
            incoming_tls = {}
        else:
            incoming_ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
            incoming_ctx.load_cert_chain(certfile=smtp.get("cert_file"), keyfile=smtp.get("key_file"))
            if tls_type == "starttls":
                incoming_tls = {"tls_context": tls_ctx, "require_starttls": True}
            elif tls_type == "implicit":
                incoming_tls = {"ssl_context": tls_ctx}

        tls_type = smtp.get("submission", {}).get("tls", "none")
        if tls_type == "none":
            submission_tls = {}
        else:
            submission_ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
            submission_ctx.load_cert_chain(certfile=smtp.get("cert_file"), keyfile=smtp.get("key_file"))
            if tls_type == "starttls":
                submission_tls = {"tls_context": tls_ctx, "require_starttls": True}
            elif tls_type == "implicit":
                submission_tls = {"ssl_context": tls_ctx}
    else:
        incoming_tls = {}
        submission_tls = {}
    incoming = Controller(
        IncomingHandler(queue),
        hostname=config.get("smtp", {}).get("incoming", {}).get("bind", "0.0.0.0"),
        port=config.get("smtp", {}).get("incoming", {}).get("port", 25),
        **incoming_tls
    )
    db = create_engine(config.get("auth_db", {}).get("url", "sqlite:////var/lib/alarick_mail/auth.db"))
    submission = Controller(
        RelayHandler(queue),
        hostname=config.get("smtp", {}).get("submission", {}).get("bind", "0.0.0.0"),
        port=config.get("smtp", {}).get("submission", {}).get("port", 587),
        authenticator=Authenticator(db),
        auth_required=True,
        **submission_tls
    )
    stop_event = asyncio.Event()
    tasks = []
    try:
        incoming.start()
        tasks.append(asyncio.create_task(incoming_processor(queue=queue, stop_event=stop_event)))
        submission.start()
        tasks.append(asyncio.create_task(relay_processor(queue=queue, stop_event=stop_event)))
        tasks.append(asyncio.create_task(retry_processor(queue=queue, stop_event=stop_event)))
        tasks.append(asyncio.create_task(bounce_processor(queue=queue, stop_event=stop_event)))
        await asyncio.Event().wait()
    finally:
        incoming.stop()
        submission.stop()
        stop_event.set()
        await asyncio.gather(*tasks)


if __name__ == '__main__':
    # logging.basicConfig(level=logging.DEBUG)
    asyncio.run(main())