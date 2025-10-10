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
    likelihood = ""
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
    max_score = 10
    if score > max_score:
        if score <= 2:
            likelihood = 'Low'
            user_email = user_email
            return render_template("index.html", likelihood=likelihood, score=score, user_email=user_email, user_subject=user_subject, user_message=user_message)
        elif score >= 3 and score <= 6:
            likelihood = 'Medium'
            return render_template("index.html", likelihood=likelihood, score=score, user_email=user_email, user_subject=user_subject, user_message=user_message)
        else:
            likelihood = 'High'
            return render_template("index.html", likelihood=likelihood, score=score, user_email=user_email, user_subject=user_subject, user_message=user_message)
    else:
        return render_template("index.html", likelihood=likelihood, score=score, user_email=user_email, user_subject=user_subject, user_message=user_message)




if __name__ == '__main__':
    app.run(debug=True)     