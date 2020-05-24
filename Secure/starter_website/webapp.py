from flask import Flask, render_template, request, redirect, url_for, flash, session
from datetime import datetime, timedelta
from db_connector.db_connector import connect_to_database, execute_query
from flask_login import LoginManager, login_user, login_required, current_user, logout_user, UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from flask_mail import Mail, Message
from threading import Thread
from itsdangerous import URLSafeTimedSerializer
from flask_talisman import Talisman
import sys  # to print to stderr
import logging
import os

#create the web application
webapp = Flask(__name__)
#load configuration from flask.cfg
webapp.config.from_pyfile('../flask.cfg')

logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(name)s %(threadName)s : %(message)s’')
# logging when on heroku
if os.environ.get('HEROKU') is not None:
    stream_handler = logging.StreamHandler()
    webapp.logger.addHandler(stream_handler)
    webapp.logger.setLevel(logging.INFO)
    webapp.logger.info('Capstone Insecure')

# sets the session timeout to 10 minutes
webapp.permanent_session_lifetime = timedelta(minutes=10)

# flask-login
'''
    Logged-in user parameters are accessible using current_user.[parameter]

    current_user.id
    current_user.username
    current_user.password
    current_user.email
    current_user.list_id
    current_user.task_id
'''

login_manager = LoginManager()
login_manager.init_app(webapp)
login_manager.login_view = '/login'
# message and cateogry that are flashed when session expires
login_manager.login_message = "Please re-login to continue"
login_manager.login_message_category = "info"

# before each request is process, this function is called
    # updates the session/cookie
@webapp.before_request
def before_request():
    session.modified = True

#TODO: Uncomment below to enforce HTTPS in production
# Talisman(webapp, content_security_policy = webapp.config['TALISMAN_CSP'])


@login_manager.user_loader
def load_user(user_id):
    db_connection = connect_to_database()  # connect to db
    query = "SELECT * FROM users WHERE `user_id` ='{}'".format(user_id)
    cursor = execute_query(db_connection, query)  # run query
    result = cursor.fetchall()
    cursor.close()
    id = result[0][0]
    username = result[0][1]
    password = result[0][2]
    email = result[0][3]
    user = User(id, username, password, email)
    db_connection.close() # close connection before returning
    return user

class User(UserMixin):
    def __init__(self, user_id, username, password, email):

        self.id = user_id
        self.username = username
        self.password = password
        self.email = email
        self.list_id = None
        self.task_id = None

#test if password meets complexity requirements
def complex_password(password):

    if len(password) >= 8 and \
            any(char.isdigit() for char in password) and \
            any(char.islower() for char in password) and \
            any(char.isupper() for char in password) and \
            any(char.islower() for char in password) and \
            any(not char.isalnum() for char in password):
        return True
    else:
        return False

#-------------------------------- Login Routes --------------------------------
@webapp.route('/')
@webapp.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('home'))

    if request.method == 'GET':
        return render_template('login.html')

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        db_connection = connect_to_database()  # connect to db

        # get info for specified username
        cursor = db_connection.cursor()
        cursor.callproc('returnUserInfo', [username, ])
        result = cursor.fetchall()
        cursor.close()

        # if the user provided a valid username
        if result:

            # get information about login attempts
            last_login_attempt = result[0][7]  # get last login attempt datetime
            current_time = datetime.now()  # get current datetime
            if last_login_attempt is None:  # check if it's users first login
                last_login_attempt = datetime.min  # set first login time to min
            difference = current_time - last_login_attempt  # calculate the difference
            seconds_in_day = 24 * 60 * 60
            difference = divmod(difference.days * seconds_in_day + difference.seconds, 60) # convert difference to a tuple of difference in minutes and seconds
            #ensure they have confirmed their email

            if result[0][4]==0:
                flash('Please confirm your email to log in', 'warning')
                db_connection.close()
                return render_template('login.html')
            # if they've failed more than 3 attempts in the last 5 minutes, don't allow login
            elif result[0][6] >= 3 and difference[0] < 5:
                webapp.logger.warning("Third attempt - Login unsuccessful, username: %s", username )
                flash('Too many failed login attempts. Try again later', 'danger')
                db_connection.close() # close connection before returning
                return render_template('login.html')

            # else check validation that user input matched query results - successful login
            elif username == result[0][1] and check_password_hash(result[0][2], password):  # check password against stored hash and salt
                # reset login_attempts to 0
                query = "UPDATE users SET login_attempts = 0 WHERE user_id = '{}'".format(result[0][0])
                cursor = execute_query(db_connection, query)  # run query
                cursor.close()

                # update last_login_attempt
                formatted_date = current_time.strftime('%Y-%m-%d %H:%M:%S')
                query = "UPDATE users SET last_login_attempt = '{}' WHERE user_id = '{}'".format(formatted_date, result[0][0])
                cursor = execute_query(db_connection, query)  # run query
                cursor.close()

                #log user in
                user = User(user_id=result[0][0], username=result[0][1], password=result[0][2], email=result[0][3])
                login_user(user)
                session.permanent = True
                webapp.logger.info("Login successful, username: %s", username )
                flash('You have been logged in!', 'success')
                next_page = request.args.get('next')
                db_connection.close() # close connection before returning
                return redirect(url_for('home'))

            # else failed login attempt
            else:
                # add one to login_attempts
                query = "UPDATE users SET login_attempts = '{}' WHERE user_id = '{}'".format(result[0][6] + 1, result[0][0])
                cursor = execute_query(db_connection, query)  # run query
                cursor.close()

                # update last_login_attempt
                formatted_date = current_time.strftime('%Y-%m-%d %H:%M:%S')
                query = "UPDATE users SET last_login_attempt = '{}' WHERE user_id = '{}'".format(formatted_date, result[0][0])
                cursor = execute_query(db_connection, query)  # run query
                cursor.close()

                webapp.logger.info("Login unsuccessful, attempt #%s, username: %s", result[0][6]+1, username )
                flash('Login Unsuccessful. Please check username and password', 'danger')
                db_connection.close() # close connection before returning
                return render_template('login.html')
        else:
            webapp.logger.warning("Login unsuccessful, username not in DB: %s", username )
            flash('Login Unsuccessful. Please check username and password', 'danger')
            return render_template('login.html')

@webapp.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have successfully logged out', 'info')
    return redirect(url_for('login'))


@webapp.route("/register", methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('home'))

    if request.method == 'GET':
        return render_template('accountCreation.html')

    if request.method == 'POST':

        email = request.form['email']
        username = request.form['username']
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        if not complex_password(password):
            flash('Password requirements not met', 'danger')
            return render_template('accountCreation.html')

        if password != confirm_password:
            flash('Password confirmation does not match password', 'danger')
            return render_template('accountCreation.html')

        db_connection = connect_to_database()

        # make sure username is unique
        query = 'SELECT `username` FROM users'
        cursor = execute_query(db_connection, query)  # run query
        rtn = cursor.fetchall()
        cursor.close()
        if (any(username in i for i in rtn)):
            flash('Username already taken, please try again', 'danger')
            db_connection.close() # close connection before returning
            return render_template('accountCreation.html')

        # make sure email is unique
        query = 'SELECT `email` FROM users'
        cursor = execute_query(db_connection, query)
        rtn = cursor.fetchall()
        cursor.close()
        if (any(email in i for i in rtn)):
            flash('Email already registered, please try again', 'danger')
            db_connection.close() # close connection before returning
            return render_template('accountCreation.html')

        # hash password with random 8 char salt - hash and salt are stored in hashed_password
        # in the same string
        hashed_password = generate_password_hash(password, salt_length=8)

        cursor = db_connection.cursor()
        cursor.callproc('addUser', [username, hashed_password, email, ])
        db_connection.commit()
        cursor.close()
        db_connection.close() # close connection before returning

        send_confirmation_email(email)
        flash('Thanks for registering. Please check your email to confirm your email address.', 'success')
        return redirect(url_for('login'))

#------------- Mail function/views --------------------------------------------

mail = Mail(webapp)

def send_async_email(msg):
    with webapp.app_context():
        mail.send(msg)

def send_email(subject, recipients, html_body, text_body):
    msg = Message(subject, recipients =recipients)
    msg.body = text_body
    msg.html = html_body
    thr = Thread(target=send_async_email, args=[msg])
    thr.start()

def send_confirmation_email(user_email):
    token = generate_confirmation_token(user_email, webapp.config['SECURITY_PASSWORD_SALT'])
    # _external=True allows it to use the url it is on to generate the url to send
    confirm_url = url_for('confirm_email', token=token, _external=True)
    html = render_template(
        'email_confirmation.html',
        confirm_url=confirm_url)
    send_email('Confirm Your Email Address', [user_email], html, "")

def send_password_reset_email(user_email):
    token = generate_confirmation_token(user_email, webapp.config['RESET_PASSWORD_SALT'])
    # _external=True allows it to use the url it is on to generate the url to send
    password_reset_url = url_for('passwordReset', token=token, _external=True)
    html = render_template(
        'email_passwordReset.html',
        password_reset_url=password_reset_url)
    send_email('Password Reset', [user_email], html, "")

#https://realpython.com/handling-email-confirmation-in-flask/
def generate_confirmation_token(user_email, securityCheck):
    serializer = URLSafeTimedSerializer(webapp.config['SECRET_KEY'])
    return serializer.dumps(user_email, salt=securityCheck)

#TODO: play with expiration (shorter) to make sure it's working as intended
def confirm_token(token, securityCheck, expiration=3600):
    serializer=URLSafeTimedSerializer(webapp.config['SECRET_KEY'])
    try:
        email=serializer.loads(
        token, salt=securityCheck,
        max_age=expiration
        )
    except:
        return False
    return email

@webapp.route('/confirm/<token>')
def confirm_email(token):
    try:
        email = confirm_token(token, webapp.config['SECURITY_PASSWORD_SALT'])
    except:
        webapp.logger.INFO("Confirmation link invalid or expired")
        flash('The confirmation link is invalid or has expired.', 'danger')

    db_connection = connect_to_database()
    query = "SELECT emailConfirmed FROM users WHERE email='{}'".format(email)
    cursor = execute_query(db_connection, query)
    rtn = cursor.fetchall()
    #if email confirmed already
    print(rtn)
    if rtn[0][0]==1:
        webapp.logger.info("Email: confirmation already processed. Email: %s", email )
        flash('Account already confirmed. Please login', 'success')
    else:
        # update emailConfirmed in DB
        current_time = datetime.now()
        query = "UPDATE users SET emailConfirmed='{}',confirmedOn='{}' WHERE email='{}'".format(1, current_time ,email)
        cursor = execute_query(db_connection, query)
        cursor.close()
        db_connection.close()
        webapp.logger.info("Email: confirmation successful. Email: %s", email)
        flash('Thank you for confirming your account!', 'success')
    return redirect(url_for('login'))

# @webapp.route("/reset_Password/<token>", methods=['GET', 'POST'])
# def password_Reset(token):
#     try:
#         email = confirm_token(token)
#     except:
#         flash('The password reset link is invalid or has expired.', 'danger')
#         return redirect(url_for('login'))
#     else:
#         return redirect(url_for('resetPassword'))

#---------------------------- Password Recovery Routes ------------------------------

@webapp.route("/recoverPassword", methods=['GET', 'POST'])
def passwordRecovery():
    if current_user.is_authenticated:
        return redirect(url_for('home'))

    if request.method == 'GET':
        return render_template('passwordRecovery.html')

    if request.method == 'POST':

        email = request.form['email']
        db_connection = connect_to_database()

        # make sure email is unique
        query = 'SELECT `email` FROM users'
        cursor = execute_query(db_connection, query)
        rtn = cursor.fetchall()
        cursor.close()
        if (not any(email in i for i in rtn)):
            webapp.logger.warning("Spoofing warning: email not registed: email: %s", email )
            flash('Email not registered, please try again', 'danger')
            db_connection.close() # close connection before returning
            return render_template('passwordRecovery.html')

        #email matches but not confirmed
        else:
            query = "SELECT emailConfirmed FROM users WHERE email = '{}'".format(email)
            cursor = execute_query(db_connection, query)
            rtn = cursor.fetchall()
            cursor.close()
            if rtn[0][0] == 0:
                webapp.logger.info("Email not confirmed before attempting password reset, email: %s", email)
                flash('Email must be confirmed before attempting a password reset.','warning')
                return render_template('login')
        #email matches
            send_password_reset_email(email)
            db_connection.close()
            flash('Please check your email to reset your password', 'success')
            return redirect(url_for('login'))

@webapp.route("/resetPassword/<token>", methods=['GET','POST'])
def passwordReset(token):
    try:
        email = confirm_token(token, webapp.config['RESET_PASSWORD_SALT'])
    except:
        webapp.logger.info("The password reset link is invalid or has expired")
        flash('The password reset link is invalid or has expired.', 'danger')
        return redirect(url_for('login'))
    #user has passed tests, allow resetting of password

    if request.method == 'GET':
        return render_template('passwordReset.html', token=token)

    if request.method =='POST':
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        if not complex_password(password):
            flash('Password requirements not met', 'danger')
            return render_template('passwordReset.html', token=token)

        if password != confirm_password:
            flash('Password confirmation does not match password', 'danger')
            return render_template('passwordReset.html', token=token)

        db_connection = connect_to_database()
        hashed_password = generate_password_hash(password, salt_length=8) # salt and hash password
        print(email)
        query = ('UPDATE `users` SET pword = %s WHERE email = %s;')
        data = (hashed_password, email)
        cursor = execute_query(db_connection, query, data)
        cursor.close()

        webapp.logger.info("Password reset. Email: %s", email)
        flash('Your password has been reset.', 'success')
        db_connection.close() # close connection before returning
        return redirect(url_for('login'))

#-------------------------------- Home (List) Routes --------------------------------
@webapp.route('/home')
@login_required
def home():
    """
    Route for the home page of a user where all of their to-do lists will be listed
    """
    context = {}  # create context dictionary
    db_connection = connect_to_database()  # connect to db

    query = "SELECT `username` FROM users WHERE `user_id` ='{}'".format(current_user.id)  # get username
    cursor = execute_query(db_connection, query)
    rtn = cursor.fetchall()
    cursor.close()
    context = {'user_name': rtn[0][0], 'user_id': current_user.id}

    query = "SELECT * FROM `lists` WHERE `user_id` ='{}'".format(current_user.id)  # get list info for a user
    cursor = execute_query(db_connection, query)
    rtn = cursor.fetchall()
    cursor.close()
    context['rows'] = rtn  # rtn = list data

    db_connection.close() # close connection before returning
    return render_template('home.html', context=context)


@webapp.route('/add_list', methods=['POST'])
@login_required
def add_list():
    """
    Route to execute query to add lists to db
    """
    db_connection = connect_to_database()
    inputs = request.form.to_dict(flat=True)  # get form inputs from request

    # Old query = """INSERT INTO `lists` (`user_id`, `name`, `description`) VALUES
    #('{}', \"{}\", \"{}\")".format(inputs['user_id'], inputs['list_name'], inputs['list_desc'])"""
    #execute_query(db_connection, query) # execute query
    cursor = db_connection.cursor()
    webapp.logger.info("Adding list. user id: %s, list_name: %s, list_desc: %s", inputs['user_id'], inputs['list_name'], inputs ['list_desc'])
    cursor.callproc('addList', [inputs['user_id'], inputs['list_name'], inputs ['list_desc'], ])
    #Source for commit: https://dev.mysql.com/doc/connector-python/en/connector-python-api-mysqlconnection-commit.html
    db_connection.commit()
    cursor.close()

    #TODO: should probably have some sort of error checking here to be sure it was added
    db_connection.close() # close connection before returning
    return redirect(url_for('home'))

@webapp.route('/delete_list/<list_id>')
@login_required
def delete_list(list_id):
    """
    Route to delete a list
    """
    db_connection = connect_to_database()
    query = "DELETE FROM `lists` WHERE `list_id` = '{}'".format(list_id)
    cursor = execute_query(db_connection, query)
    cursor.close()

    webapp.logger.info("Deleting list. userid: %s, listid: %s", current_user.id, list_id)
    flash('The list has been deleted.', 'info')
    db_connection.close() # close connection before returning
    return redirect(url_for('home'))


@webapp.route('/update_list/<list_id>', methods=['POST', 'GET'])
@login_required
def update_list(list_id):
    """
    Display list update form and process any updates using the same function
    """
    db_connection = connect_to_database()

    # display current data
    if request.method == 'GET':
        query = "SELECT * FROM `lists` WHERE `list_id` ='{}'".format(list_id)  # get info of list
        cursor = execute_query(db_connection, query)
        rtn = cursor.fetchall()
        cursor.close()
        context = {'list_id': rtn[0][0], 'list_name': rtn[0][2], 'list_desc': rtn[0][3]}
        db_connection.close() # close connection before returning
        return render_template('update_list.html', context=context)
    elif request.method == 'POST':
        query = "UPDATE `lists` SET `name` = %s, `description` = %s WHERE `list_id` = %s"
        data = (request.form['list_name'], request.form['list_desc'], list_id)
        cursor = execute_query(db_connection, query, data)
        cursor.close()
        db_connection.close() # close connection before returning
        webapp.logger.info("Update list. userid: %s, list_id: %s, list_name: %s, list_desc: %s", current_user.id, list_id, request.form['list_name'], request.form['list_desc'])
        return redirect('/home')


#-------------------------------- Task Routes --------------------------------

@webapp.route('/tasks/<list_id>')
@login_required
def tasks(list_id):
    """
    Route for the tasks page of a user's list where all of the tasks of a to do list are shown
    """
    db_connection = connect_to_database()  # connect to db

    # check if requested list belongs to the user
    query = "SELECT `user_id` FROM lists WHERE `list_id` = '{}'".format(list_id)
    cursor = execute_query(db_connection, query)
    rtn = cursor.fetchall()
    cursor.close()
    if rtn[0][0] != current_user.id:
        print(rtn)
        db_connection.close() # close connection before returning
        webapp.logger.warning("Invalid access to view list. userid: %s", current_user.id)
        return redirect(url_for('invalid_access'))

    context = {}  # create context dictionary

    query = "SELECT `name`, `description` FROM lists WHERE `list_id` = '{}'".format(list_id)  # get name/desc of list
    cursor = execute_query(db_connection, query)
    rtn = cursor.fetchall()  # run query
    cursor.close()
    context = {'list_name': rtn[0][0], 'list_desc': rtn[0][1], 'list_id': list_id}

    cursor = db_connection.cursor()
    cursor.callproc('returnTasks', [list_id, ])
    rtn = cursor.fetchall()
    cursor.close()
    context['rows'] = rtn  # rtn = tasks data

    query = "SELECT * from dataTypes" # get list of all types of tasks
    cursor = execute_query(db_connection, query)
    rtn = cursor.fetchall()
    cursor.close()
    context['taskTypes'] = rtn

    db_connection.close() # close connection before returning
    webapp.logger.info("View lists. User_id: %s", current_user.id)
    return render_template('tasks.html', context=context)

@webapp.route('/invalid_access')
@login_required
def invalid_access():
    """
    Route if a user tries to access another users list of tasks
    """
    return render_template('invalid_access.html', context = None)

@webapp.route('/add_task', methods=['POST'])
@login_required
def add_task():
    """
    Route to execute query to add task to db
    """
    db_connection = connect_to_database()
    inputs = request.form.to_dict(flat=True)  # get form inputs from request

    #query = """INSERT INTO `tasks` (`list_id`, `dataType_id`, `description`, `completed`)
    #VALUES ('{}', '{}', \"{}\", '{}')".format(inputs['list_id'], inputs['task_type'], inputs['task_desc'], inputs['task_comp'])"""
    #execute_query(db_connection, query).fetchall()  # execute query
    cursor = db_connection.cursor()
    cursor.callproc('addTask', [inputs['list_id'], inputs['task_type'], inputs['task_desc'], inputs['task_comp'], ])
    #Source for commit: https://dev.mysql.com/doc/connector-python/en/connector-python-api-mysqlconnection-commit.html
    db_connection.commit()
    cursor.close()
    db_connection.close() # close connection before returning
    webapp.logger.info("List added. User_id: %s, list_id", current_user.id, inputs['list_id'])
    return redirect("/tasks/" + inputs['list_id'])

@webapp.route('/delete_task/<list_id>/<task_id>')
@login_required
def delete_task(task_id, list_id):
    """
    Route to delete a task
    """
    db_connection = connect_to_database()
    query = "DELETE FROM `tasks` WHERE `task_id` = '{}'".format(task_id)
    cursor = execute_query(db_connection, query)
    rtn = cursor.fetchall()
    cursor.close()
    db_connection.close() # close connection before returning
    webapp.logger.info("Delete from tasks. User_id: %s, list_id: %s, task_id: %s", current_user.id, list_id, task_id)
    return redirect('/tasks/' + list_id)


@webapp.route('/update_task/<list_id>/<task_id>', methods=['POST', 'GET'])
@login_required
def update_task(list_id, task_id):
    """
    Display task update form and process any updates using the same function
    """
    db_connection = connect_to_database()

    # display current data
    if request.method == 'GET':
        query = "SELECT * FROM `tasks` WHERE `task_id` ='{}'".format(task_id)  # get info of task
        cursor = execute_query(db_connection, query)
        rtn = cursor.fetchall()
        cursor.close()
        context = {'task_id': rtn[0][0], 'task_type': rtn[0][2], 'task_desc': rtn[0][3], 'task_comp': rtn[0][4], 'list_id': list_id}

        query = "SELECT * from dataTypes" # get list of all types of tasks
        cursor = execute_query(db_connection, query)
        rtn = cursor.fetchall()  # run query
        cursor.close()
        context['taskTypes'] = rtn
        webapp.logger.info("View tasks. User_id: %s", current_user.id)
        db_connection.close() # close connection before returning
        return render_template('update_task.html', context=context)
    elif request.method == 'POST':
        query = "UPDATE `tasks` SET `dataType_id` = %s, `description` = %s, `completed` = %s WHERE `task_id` = %s"
        data = (request.form['task_type'], request.form['task_desc'], request.form['task_comp'], task_id)
        cursor = execute_query(db_connection, query, data)
        rtn = cursor.fetchall()
        cursor.close()
        db_connection.close()
        webapp.logger.info("Update tasks. User_id: %s, task_id: %s", current_user.id, task_id)
        return redirect('/tasks/' + list_id)
