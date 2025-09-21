from flask import Flask
from flask import render_template
from flask import url_for
from flask import request
from flask import redirect
from email_check import valid_check


app = Flask(__name__) # static_folder='static', template_folder='templates' are default

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/Email', methods=['POST'])
def check():
    user = request.form['email_input']
    valid_check(user)
    if valid_check(user) == True:
        return '<h1>Welcome!!!</h1>'
    else:
        return '<h1>invalid credentials!</h1>'

if __name__ == '__main__':
    app.run(debug=True)     