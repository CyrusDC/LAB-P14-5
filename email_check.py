import csv
import re

DATASET_PATH = 'dataset/CEAS_08.csv'

def load_emails(dataset_path):
    emails = []
    with open(dataset_path, newline='', encoding='utf-8') as csvfile:
        reader = csv.DictReader(csvfile)
        for row in reader:
            emails.append(row)
    return emails

def phishing_score(email):
    suspicious_keywords = ['urgent', 'verify', 'account', 'password', 'login', 'click', 'update', 'security',
        'win', 'free', 'gift', 'prize', 'limited', 'offer', 'claim', 'alert', 'confirm', 'suspend',
        'locked', 'unusual', 'activity', 'refund', 'payment', 'invoice', 'bank', 'reset', 'important',
        'attention', 'immediately', 'action required', 'click here', 'credentials']
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

    # Rule 3: Simple check for links
    if 'http' in body or 'www' in body:
        points += 1

    # Rule 4: Mismatched sender and reply-to
    reply_to = email.get('reply-to', '').lower()
    if reply_to != sender:
        points += 1

    # Rule 5: Risky attachment types
    risky_extensions = ['.exe', '.zip', '.scr', '.js', '.bat', '.com', '.vbs', '.jar', '.msi']
    attachments = email.get('attachments', '').lower()
    for ext in risky_extensions:
        if ext in attachments:
            points += 1
            break

    # Rule 6: Poor grammar or spelling mistakes (simple check)
    # This is a basic check for common mistakes
    grammar_mistakes = ['your account are', 'click here now', 'dear customer', 'dear user', 'recieve', 'securty', 'immediatly', 'informtion']
    for mistake in grammar_mistakes:
        if mistake in body:
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

def main():
    emails = load_emails(DATASET_PATH)
    results = []
    for email in emails:
        score = phishing_score(email)
        if score >= 10:
            likelihood = 'High'
        elif score > 2 and score <= 5:
            likelihood = 'Medium'
        else:
            likelihood = 'Low'
        results.append({'id': email.get('id', ''), 'Likelihood': likelihood})
    #Print summary
    print(f'Total emails: {len(results)}')
    print('Phishing likelihood scores:')
    for r in results:
        print(f"Email ID: {r['id']}, Likelihood: {r['Likelihood]}")']}")

if __name__ == '__main__':
    main()

#import pandas as pd

#def valid_check(email):
#    fake_emails = str(read_csv())
#    if email in fake_emails:
#        return False
#    else:
#        return True

#def read_csv():
#    csvFile = pd.read_csv('dataset/CEAS_08.csv')
#    sender_dict = dict(csvFile['sender'])
#    return sender_dict


