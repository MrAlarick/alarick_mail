from databases import Database
import asyncio
import bcrypt
import dns.resolver
import aiosmtplib
import smtplib, ssl
from sqlalchemy import create_engine, text


def main():
    db = create_engine("sqlite:////var/lib/alarick_mail/auth.db")
    with db.connect() as con:
        print(con.execute(text("SELECT password from virtual_users where username = 'test@alarick.org'")).first()[0])
    #await db.execute(query="create table if not exists virtual_users (id integer primary key, domain_id integer not null, username text not null, password text not null, quota integer not null default 1024);")
    #await db.execute(query="insert into virtual_users(username, password, domain_id) values (:name, :pw, 0)", values={"name": "test@alarick.org", "pw": bcrypt.hashpw(b"password", bcrypt.gensalt()).decode("utf-8")})
    #await db.execute(query="update virtual_users set password = :pw where username = 'test@alarick.org'", values={"pw": bcrypt.hashpw(b"password", bcrypt.gensalt()).decode("utf-8")})
    #r = await db.fetch_one(query="select username, password from virtual_users where username = 'test@alarick.org'")
    #print(r[0], r[1], bcrypt.checkpw(b"password", r[1].encode("utf-8")))

if __name__ == "__main__":
    #main()
    #r = dns.resolver.resolve("alarick.org", "MX")
    #print(tuple(i.exchange.to_text() for i in r))
    #asyncio.run(main())



    smtp_server = "localhost"
    port = 587  # For starttls
    sender_email = "test@alarick.org"
    password = "password"

    # Create a secure SSL context
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    # Try to log in to server and send email
    try:
        server = smtplib.SMTP(smtp_server, port)
        server.set_debuglevel(1)
        server.ehlo()  # Can be omitted
        #server.starttls(context=context)  # Secure the connection
        #server.ehlo()  # Can be omitted
        server.login(sender_email, password)
        server.sendmail(sender_email, "alarick@alarick.org", """From: test@alarick.org
To: alarick@alarick.org
Subject: Test

Test""")
    except Exception as e:
        # Print any error messages to stdout
        print(e)
    finally:
        server.quit()