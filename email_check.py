import csv
import re
import sys
import threading

# Ensure stdout/stderr can handle Unicode on Windows consoles. This forces
# a UTF-8 encoding with replacement for characters that can't be encoded
# which prevents UnicodeEncodeError from crashing the script when printing
# email headers that contain non-CP1252 characters.
try:
    # Python 3.7+ provides reconfigure
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
    sys.stderr.reconfigure(encoding='utf-8', errors='replace')
except Exception:
    # Fallback for other environments
    try:
        import io
        sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
        sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', errors='replace')
    except Exception:
        # If even that fails, continue; prints may still error but we'll try.
        pass

# Toggle verbose debugging output
VERBOSE = False

# Defer importing language_tool_python until the background initializer runs
# to avoid blocking module import if the package or Java is missing.
language_tool_python = None

maxInt = sys.maxsize

while True:
    try:
        csv.field_size_limit(maxInt)
        break
    except OverflowError:
        maxInt = int(maxInt/10)

DATASET_PATH = 'dataset/CEAS_08.csv'


def init_language_tool(lang='en-US'):
    """Initialize LanguageTool once. Returns tool or None if initialization fails.

    Note: language_tool_python requires Java. If Java is not available this will
    fail and return None so the rest of the script can continue with a simple
    fallback check.
    """
    try:
        tool = language_tool_python.LanguageTool(lang)
        return tool
    except Exception as e:
        print(f"Warning: LanguageTool init failed: {e}")
        return None


def check_grammar_and_spelling(text, tool, max_chars=20000):
    """Return a list of unique LanguageTool matches for the provided text.

    - Truncates very long inputs for performance.
    - Deduplicates overlapping matches by (offset, errorLength).
    """
    if not tool or not text:
        return []
    snippet = text[:max_chars]
    matches = tool.check(snippet)
    seen = set()
    unique = []
    for m in matches:
        span = (m.offset, getattr(m, 'errorLength', 0))
        if span not in seen:
            seen.add(span)
            unique.append(m)
    return unique


# Initialize the LanguageTool instance once in the background to avoid
# blocking the main thread (language_tool_python may try to start Java).
# TOOL will be set to a LanguageTool instance if initialization succeeds;
# otherwise it will remain None and the code will fall back to the simple checks.
TOOL = None
_TOOL_READY = False

def _init_tool_bg(lang='en-US'):
    """Background initializer for LanguageTool. Runs in a daemon thread."""
    global TOOL, _TOOL_READY
    # Try to import language_tool_python here (in background) so the main
    # thread isn't blocked by the import or by Java starting.
    try:
        import language_tool_python as _lt
        globals()['language_tool_python'] = _lt
    except Exception as e:
        if VERBOSE:
            print(f'language_tool_python import failed in background: {e}')
        globals()['language_tool_python'] = None
        _TOOL_READY = True
        return
    try:
        TOOL = init_language_tool(lang)
    except Exception as e:
        if VERBOSE:
            print(f'LanguageTool init failed in background: {e}')
        TOOL = None
    _TOOL_READY = True

# Start background initialization but don't wait for it. This prevents the
# script from hanging if LanguageTool/Java is unavailable or slow to start.
try:
    threading.Thread(target=_init_tool_bg, args=('en-US',), daemon=True).start()
except Exception:
    # If threading fails for any reason, fall back to no tool.
    TOOL = None
    _TOOL_READY = True
if VERBOSE:
    print('Started LanguageTool background initialization (non-blocking).')



# Load dataset and return a dict
def load_emails(dataset_path):
    emails = []
    with open(dataset_path, newline='', encoding='utf-8') as csvfile:
        reader = csv.DictReader(csvfile)
        for row in reader:
            emails.append(row)
    return emails


# function for email checks
def phishing_score(email):
    suspicious_keywords = ['urgent', 'verify', 'account', 'password', 'login', 'click', 'update', 'security',
        'win', 'free', 'gift', 'prize', 'limited', 'offer', 'claim', 'alert', 'confirm', 'suspend',
        'locked', 'unusual', 'activity', 'refund', 'payment', 'invoice', 'bank', 'reset', 'important',
        'attention', 'immediately', 'action required', 'click here', 'credentials', 'download', 'Browser',
        'Edge', 'Chrome', 'Firefox','.dll', 'Crypt', 'Encry', 'Key', 'Passw', 'username', 'Login','Credential',
        'load', 'Rundll', 'Sql', 'select', 'Run', '.cmd','encode', 'base64', 'Powershell', 'mine', 'game',
        'hack', 'clipboard', 'GetAsyncKeyState', 'mouse', 'hook', 'bypass', 'monitor', 'Firewall','ransom',
        'payload', 'HKEY', 'VMcheck', 'Virus', 'DOS', 'task', 'rat','ftp', 'smtp', 'socket', 'connect',
        'send', 'recv', 'autorun', 'startup','services.msc', 'svchost', 'regedit', 'regsvr32', 'vmware', 'vbox',
        'qemu','xen', 'sandbox', 'ollydbg', 'windbg', 'ida', 'trojan', 'worm', 'backdoor','rootkit', 'keylogger',
        'stealer', 'exploit', 'shellcode', 'xor', 'base64','createremotethread', 'virtualallocex', 'writeprocmemory',
        'loadlibrary','getprocaddress', 'bitcoin', 'monero', 'ethereum', 'wallet', 'miner', 'pool','stratum', 'overwrite', 'killprocess']
    suspicious_domains = ['.ru', '.cn', '.tk', '.ml', '.biz', '.info', '.top', '.xyz', '.club', '.online', '.work',
        '.cf', '.ga', '.gq', '.pw', '.cc', '.su', '.io', '.scam', '.phish']
    points = 0

    # Rule 1: Add a point for every suspicious keyword detected
    body = email.get('body', '').lower()
    for keyword in suspicious_keywords:
        if keyword in body:
            points += 1

    # Rule 2: Check sender domain
    sender = email.get('from', '').lower()
    if any(sender.endswith(domain) for domain in suspicious_domains):
        points += 1

    # Rule 3: URL analysis
    url_shorteners = ['bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly', 'is.gd', 'buff.ly', 'adf.ly', 'bit.do', 'cutt.ly', 'shorte.st']
    url_pattern = re.compile(r'https?://[^\s]+')
    urls = url_pattern.findall(body)
    for url in urls:
        # Check for URL shorteners
        if any(short in url for short in url_shorteners):
            points += 1
        # Check for punycode/homograph attacks
        if 'xn--' in url:
            points += 1
        # Check for suspicious subdomains (e.g., too many dots)
        domain = re.sub(r'https?://', '', url).split('/')[0]
        if domain.count('.') > 3:
            points += 1
        # Stub: Threat intelligence API/blacklist check (to be implemented)
        # if is_blacklisted(url):
        #     points += 2
    if urls:
        points += 1  # General point for having links


    # Rule 4: Mismatched sender and reply-to
    reply_to = email.get('reply-to', '').lower()
    if reply_to != sender:
        points += 1

    # Rule 5: Risky attachment types
    risky_extensions = ['.exe', '.zip', '.scr', '.js', '.bat', '.com', '.vbs', '.jar', '.msi', '.ps1', '.hta', '.wsf', '.scr','.pif', '.pdb']
    attachments = email.get('attachments', '').lower()
    for ext in risky_extensions:
        if ext in attachments:
            points += 1
            break

    # Rule 6: Poor grammar or spelling mistakes (simple check)
    # This is a basic check for common mistakes
    # grammar_mistakes = ['your account are', 'click here now', 'dear customer', 'dear user', 'recieve', 'securty', 'immediatly', 'informtion']
    # for mistake in grammar_mistakes:
    #     if mistake in body:
    # Use LanguageTool if available; otherwise fall back to a tiny hardcoded check
    grammar_matches = []
    if TOOL:
        try:
            grammar_matches = check_grammar_and_spelling(body, TOOL)
        except Exception as e:
            if VERBOSE:
                print(f"LanguageTool check failed: {e}")
            grammar_matches = []
    else:
        # Very small fallback heuristic for common misspellings/phrases
        fallback_mistakes = ['recieve', 'securty', 'immediatly', 'informtion', 'click here now', 'your account are']
        for fm in fallback_mistakes:
            if fm in body:
                grammar_matches.append(fm)

    # Count (and optionally print) the grammar/spelling findings
    for match in grammar_matches:
        if VERBOSE:
            # match may be a Match object or a simple string from fallback
            if hasattr(match, 'message'):
                print(f"Typo/Error: {match.message} -> {getattr(match, 'context', '')}")
            else:
                print(f"Typo/Error (fallback): {match}")
        points += 1

    # Rule 7: Odd hours (simple check, if 'date' field exists)
    # Assume date is in format 'YYYY-MM-DD HH:MM:SS'
    date_str = email.get('date', '')
    if date_str:
        try:
            hour = int(date_str.split()[1].split(':')[0])
            if hour < 6 or hour > 22:
                points += 1
        except Exception:
            pass

    # Rule 8: Excessive exclamation marks or ALL CAPS
    if body.count('!') > 3:
        points += 1
    if body.isupper():
        points += 1

    return points

def email_main():
    if VERBOSE:
        print(f'Loading emails from {DATASET_PATH}...')
    emails = load_emails(DATASET_PATH)
    if VERBOSE:
        print(f'Loaded {len(emails)} emails')
    results = []
    for email in emails:
        score = phishing_score(email)
        if score <= 2:
            likelihood = 'Low'
            # likelihood = 'High'
        elif score >= 3 and score <= 6:
            likelihood = 'Medium'
        else:
            likelihood = 'High'
            # likelihood = 'Low'
        # results.append({'id': email.get('id', ''), 'Likelihood': likelihood})
        results.append({'id': email.get('sender', ''), 'Likelihood': likelihood})
    #Print summary
    print(f'Total emails: {len(results)}')
    print('Phishing likelihood scores:')
    for r in results:
        print(f"Email ID: {r['id']}, Likelihood: {r['Likelihood']}, score: {score}")



if __name__ == '__main__':
    email_main()


