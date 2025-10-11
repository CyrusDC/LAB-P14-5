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
    # Takes input from the form
    user_email = request.form['email_input']
    user_subject = request.form['email_subject']
    user_message = request.form['message']

    # Takes all the input and place it in a Dictionary so that the function can read the input  
    user_dict = {                                            
        'from': user_email,
        'body': user_subject + "\n" + user_message
    }

    # Adds the total score of the whole email
    score = phishing_score(user_dict)
    max_score = 100

    # Checks if the score is more than the max_score, it will default to 100
    if score > max_score:
        score = max_score

    # Shows the output of the email whether it is low, mid or high
    if score <= 32:
        likelihood = 'Low'
    elif score >= 33 and score <= 69:
        likelihood = 'Medium'
    else:
        likelihood = 'High'
    return render_template("index.html", likelihood=likelihood, user_email=user_email, score=score, user_subject=user_subject, user_message=user_message)



if __name__ == '__main__':
    app.run(debug=True)     