from flask import Flask, render_template, request, redirect, url_for, flash
from db_connector.db_connector import connect_to_database, execute_query
from flask_login import LoginManager, login_user, login_required, current_user, logout_user, UserMixin

import sys  # to print to stderr



#create the web application
webapp = Flask(__name__)
#webapp = Flask(__name__, static_url_path='/static')
webapp.secret_key = b'_5#y2L"F4Q8z\n\xec]/'


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


@login_manager.user_loader
def load_user(user_id):
    db_connection = connect_to_database()  # connect to db
    query = "SELECT * FROM users WHERE `user_id` ='{}'".format(user_id)
    result = execute_query(db_connection, query).fetchall()  # run query
    id = result[0][0]
    username = result[0][1]
    password = result[0][2]
    email = result[0][3]
    user = User(id, username, password, email)
    db_connection.close() # close connection before returning result
    return user

class User(UserMixin):
    def __init__(self, user_id, username, password, email):

        self.id = user_id
        self.username = username
        self.password = password
        self.email = email
        self.list_id = None
        self.task_id = None

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

        db_connection = connect_to_database() # connect to db
        #old query (more secure)
        #query = "SELECT * FROM users WHERE `username` ='{}'".format(username)

        query = "SELECT * FROM users WHERE `username`='{}' AND pword='{}'".format(username, password)
        # query above is equivalient to: query = "SELECT * FROM users WHERE username= '" + username + "' AND pword = '"+password+"'"

        #Blind insertion: username = doesntmatter
            #password = doesntmatter'OR user_id='1
        #tautalogy:username = doesntmatter  password = blah' OR user_id like '%%

        result = execute_query(db_connection, query).fetchall()  # run query
        if result:
            #removed validation of user entry to allow for SQL injection
            #if username == result[0][1] and password == result[0][2]:
            user = User(user_id=result[0][0], username=result[0][1], password=result[0][2], email=result[0][3])
            login_user(user)
            flash('You have been logged in!', 'success')
            next_page = request.args.get('next')
            db_connection.close() # close connection before returning
            return redirect(url_for('home'))

        flash('Login Unsuccessful. Please check username and password', 'danger')
        db_connection.close() # close connection before returning
        return render_template('login.html')

@webapp.route('/reset_database', methods=['POST'])
def reset_database():
    db_connection = connect_to_database()
    query = "CALL reset_database()"
    execute_query(db_connection, query)
    flash('Reset database was successful', 'success')
    db_connection.close() # close connection before returning
    return render_template('login.html')


@webapp.route('/logout')
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

        if password != confirm_password:
            flash('Password confirmation does not match password', 'danger')
            return render_template('accountCreation.html')

        db_connection = connect_to_database()

        # make sure username is unique
        query = 'SELECT `username` FROM users'
        rtn = execute_query(db_connection, query).fetchall()  # run query
        if (any(username in i for i in rtn)):
            flash('Username already taken, please try again', 'danger')
            db_connection.close() # close connection before returning
            return render_template('accountCreation.html')

        # make sure email is unique
        query = 'SELECT `email` FROM users'
        rtn = execute_query(db_connection, query).fetchall()  # run query
        if (any(email in i for i in rtn)):
            flash('Email already registered, please try again', 'danger')
            db_connection.close() # close connection before returning
            return render_template('accountCreation.html')

        query = ('INSERT INTO `users` '
                 '(`user_id`, `username`, `pword`, `email`) '
                 'VALUES (NULL, %s, %s, %s);')
        data = (username, password, email)
        execute_query(db_connection, query, data)

        flash('Your account has been created. You may now log in.', 'success')
        db_connection.close() # close connection before returning
        return redirect(url_for('login'))


#----------------- Password Recovery Routes ------------------------------------

@webapp.route("/recoverPassword", methods=['GET', 'POST'])
def passwordRecovery():
    if current_user.is_authenticated:
        return redirect(url_for('home'))

    if request.method == 'GET':
        return render_template('passwordRecovery.html')

    if request.method == 'POST':

        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        if password != confirm_password:
            flash('Password confirmation does not match password', 'danger')
            return render_template('passwordRecovery.html')

        db_connection = connect_to_database()

        # make sure email is unique
        query = 'SELECT `email` FROM users'
        cursor = execute_query(db_connection, query)
        rtn = cursor.fetchall()
        cursor.close()
        if (not any(email in i for i in rtn)):
            flash('Email not registered, please try again', 'danger')
            db_connection.close() # close connection before returning
            return render_template('passwordRecovery.html')

        query = ('UPDATE `users` '
                 'SET pword = %s WHERE email = %s;')
        data = (password, email)
        cursor = execute_query(db_connection, query, data)
        cursor.close()

        flash('Your password has been reset. You may now log in.', 'success')
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
    rtn = execute_query(db_connection, query).fetchall()  # run query
    context = {'user_name': rtn[0][0], 'user_id': current_user.id}

    query = "SELECT * FROM `lists` WHERE `user_id` ='{}'".format(current_user.id)  # get list info for a user
    rtn = execute_query(db_connection, query).fetchall()  # run query
    context['rows'] = rtn  # rtn = list data

    db_connection.close() # close connection before returning
    return render_template('home.html', context=context)

@webapp.route('/reset_database/home', methods=['POST'])
def reset_database_home():
    db_connection = connect_to_database()
    query = "CALL reset_database()"
    execute_query(db_connection, query)
    flash('Reset database was successful', 'success')
    db_connection.close() # close connection before returning
    return redirect(url_for('home'))

@webapp.route('/add_list', methods=['POST'])
# @login_required
def add_list():
    """
    Route to execute query to add lists to db
    """
    db_connection = connect_to_database()
    inputs = request.form.to_dict(flat=True)  # get form inputs from request

    query = "INSERT INTO `lists` (`user_id`, `name`, `description`) VALUES ('{}', '{}', '{}')".format(inputs['user_id'], inputs['list_name'], inputs['list_desc'])
    execute_query(db_connection, query) # execute query

    db_connection.close() # close connection before returning
    return redirect(url_for('home'))


@webapp.route('/delete_list/<list_id>')
# @login_required
def delete_list(list_id):
    """
    Route to delete a list
    """
    db_connection = connect_to_database()
    query = "DELETE FROM `lists` WHERE `list_id` = {}".format(list_id)
    execute_query(db_connection, query)
    flash('The list has been deleted.', 'info')
    db_connection.close() # close connection before returning
    return redirect(url_for('home'))


@webapp.route('/update_list/<list_id>', methods=['POST', 'GET'])
def update_list(list_id):
    """
    Display list update form and process any updates using the same function
    """
    db_connection = connect_to_database()

    # display current data
    if request.method == 'GET':
        query = "SELECT * FROM `lists` WHERE `list_id` ='{}'".format(list_id)  # get info of list
        rtn = execute_query(db_connection, query).fetchall()  # run query
        context = {'list_id': rtn[0][0], 'list_name': rtn[0][2], 'list_desc': rtn[0][3]}
        db_connection.close() # close connection before returning
        return render_template('update_list.html', context=context)
    elif request.method == 'POST':
        query = "UPDATE `lists` SET `name` = %s, `description` = %s WHERE `list_id` = %s"
        data = (request.form['list_name'], request.form['list_desc'], list_id)
        rtn = execute_query(db_connection, query, data)
        db_connection.close() # close connection before returning
        return redirect('/home')


#-------------------------------- Task Routes --------------------------------
@webapp.route('/tasks/<list_id>')
def tasks(list_id):
    """
    Route for the tasks page of a user's list where all of the tasks of a to do list are shown
    """
    db_connection = connect_to_database()  # connect to db

    # this is where we SHOULD check if requested list belongs to the user

    context = {}  # create context dictionary

    query = "SELECT `name`, `description` FROM lists WHERE `list_id` = {}".format(list_id)  # get name/desc of list
    rtn = execute_query(db_connection, query).fetchall()  # run query
    context = {'list_name': rtn[0][0], 'list_desc': rtn[0][1], 'list_id': list_id}

    query = "SELECT tasks.task_id, tasks.list_id, tasks.dataType_id, tasks.description, tasks.completed, dataTypes.name FROM `tasks` JOIN `dataTypes` ON tasks.dataType_id = dataTypes.dataType_id WHERE list_id = {}".format(list_id)  # get info of tasks on list
    rtn = execute_query(db_connection, query).fetchall()  # run query
    context['rows'] = rtn  # rtn = tasks data

    query = "SELECT * from dataTypes" # get list of all types of tasks
    rtn = execute_query(db_connection, query).fetchall()  # run query
    context['taskTypes'] = rtn

    db_connection.close() # close connection before returning
    return render_template('tasks.html', context=context)


@webapp.route('/invalid_access')
# @login_required
def invalid_access():
    """
    Route if a user tries to access another users list of tasks
    """
    return render_template('invalid_access.html', context = None)



@webapp.route('/add_task', methods=['POST'])
def add_task():
    """
    Route to execute query to add task to db
    """
    db_connection = connect_to_database()
    inputs = request.form.to_dict(flat=True)  # get form inputs from request

    query = "INSERT INTO `tasks` (`list_id`, `dataType_id`, `description`, `completed`) VALUES ('{}', '{}', '{}', '{}')".format(inputs['list_id'], inputs['task_type'], inputs['task_desc'], inputs['task_comp'])
    execute_query(db_connection, query).fetchall()  # execute query

    db_connection.close() # close connection before returning
    return redirect("/tasks/" + inputs['list_id'])


@webapp.route('/delete_task/<list_id>/<task_id>')
def delete_task(task_id, list_id):
    """
    Route to delete a task
    """
    db_connection = connect_to_database()
    query = "DELETE FROM `tasks` WHERE `task_id` = '{}'".format(task_id)
    execute_query(db_connection, query).fetchall()
    db_connection.close() # close connection before returning
    return redirect('/tasks/' + list_id)


@webapp.route('/update_task/<list_id>/<task_id>', methods=['POST', 'GET'])
def update_task(list_id, task_id):
    """
    Display task update form and process any updates using the same function
    """
    db_connection = connect_to_database()

    # display current data
    if request.method == 'GET':
        query = "SELECT * FROM `tasks` WHERE `task_id` = {}".format(task_id)  # get info of task
        rtn = execute_query(db_connection, query).fetchall()  # run query
        context = {'task_id': rtn[0][0], 'task_type': rtn[0][2], 'task_desc': rtn[0][3], 'task_comp': rtn[0][4], 'list_id': list_id}

        query = "SELECT * from dataTypes" # get list of all types of tasks
        rtn = execute_query(db_connection, query).fetchall()  # run query
        context['taskTypes'] = rtn

        db_connection.close() # close connection before returning
        return render_template('update_task.html', context=context)
    elif request.method == 'POST':
        query = "UPDATE `tasks` SET `dataType_id` = %s, `description` = %s, `completed` = %s WHERE `task_id` = %s"
        data = (request.form['task_type'], request.form['task_desc'], request.form['task_comp'], task_id)
        rtn = execute_query(db_connection, query, data)
        db_connection.close() # close connection before returning
        return redirect('/tasks/' + list_id)
