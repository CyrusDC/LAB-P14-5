import pandas as pd


def valid_check(email):
    fake_emails = str(read_csv())
    if email in fake_emails:
        return False
    else:
        return True

def read_csv():
    csvFile = pd.read_csv('dataset/CEAS_08.csv')
    sender_dict = dict(csvFile['sender'])
    return sender_dict


