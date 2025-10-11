from flask import Flask
from flask import render_template
from flask import request
from email_check import phishing_score


app = Flask(__name__) # static_folder='static', template_folder='templates' are default

# This part routes the Flask App to the index html
@app.route('/')
def index():
    return render_template('index.html')

# This part handles the input from the form from index html and updates it when the submit button is pressed
@app.route('/Email', methods=['POST'])
def check():
    likelihood = ""  # Local Var

    # Takes input from the form
    user_email = request.form['email_input']
    user_subject = request.form['email_subject']
    user_message = request.form['message']

    # Takes all the input and place it in a Dictionary so that the function can read the input  
    user_dict = {                                            
        'from': user_email,
        'body': user_subject + "\n" + user_message
    }

    # Imports the function to check the email and give a score
    user_check_email = phishing_score(user_dict) 
    user_check_subject = phishing_score(user_dict)
    user_check_message = phishing_score(user_dict)

    # Adds the total score of the whole email
    score = user_check_email + user_check_message + user_check_subject
    max_score = 100

    # Shows the output of the email whether it is low, mid or high
    if score < max_score:
        if score <= 32:
            likelihood = 'Low'
            user_email = user_email
            return render_template("index.html", likelihood=likelihood, user_email=user_email, user_subject=user_subject, user_message=user_message)
        elif score >= 33 and score <= 66:
            likelihood = 'Medium'
            return render_template("index.html", likelihood=likelihood, user_email=user_email, user_subject=user_subject, user_message=user_message)
        else:
            likelihood = 'High'
            return render_template("index.html", likelihood=likelihood, user_email=user_email, user_subject=user_subject, user_message=user_message)
    else:
        likelihood = 'High'
        score = max_score
        return render_template("index.html", likelihood=likelihood, user_email=user_email, user_subject=user_subject, user_message=user_message)




if __name__ == '__main__':
    app.run(debug=True)     