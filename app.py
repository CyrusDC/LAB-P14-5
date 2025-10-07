from flask import Flask
from flask import render_template
from flask import url_for
from flask import request
from email_check import phishing_score


app = Flask(__name__) # static_folder='static', template_folder='templates' are default

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/Email', methods=['POST'])
def check():
    user_email = request.form['email_input']
    user_subject = request.form['email_subject']
    user_message = request.form['message']
    user_dict = {
        'from': user_email,
        'body': user_subject + "\n" + user_message
    }
    user_check_email = phishing_score(user_dict)
    user_check_subject = phishing_score(user_dict)
    user_check_message = phishing_score(user_dict)
    score = user_check_email + user_check_message + user_check_subject
    if score >= 10:
        likelihood = 'High'
        return '<h1>likelihood high</h1>'
    elif score > 2 and score <= 5:
        likelihood = 'Medium'
        return '<h1>likelihood medium</h1>'
    else:
        likelihood = 'Low'
        return '<h1>likelihood low</h1>'




if __name__ == '__main__':
    app.run(debug=True)     