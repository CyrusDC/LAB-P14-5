import pandas as pd


def valid_check(email):
    if "@" in email and "." in email:
        return True
    else:
        return False # Recursively call the function until a valid email is entered

def read_csv():
    csvFile = pd.read_csv('dataset\CEAS_08.csv')
    print(csvFile)

read_csv()