import minitwit
import time
import uuid
from sqlite3 import dbapi2 as sqlite3
from flask import Flask, request, jsonify, g, make_response, abort, _app_ctx_stack
from flask_basicauth import BasicAuth
from werkzeug import check_password_hash, generate_password_hash
from sqlite3 import OperationalError
from cassandra.cluster import Cluster
from cassandra.query import dict_factory

cluster = Cluster(['127.0.0.1'])


#configuration
#DATABASE = 'database.db'
#DATABASE = 'userdata'
KEYSPACE = 'userdata'
PER_PAGE = 30
DEBUG = True
SECRET_KEY = b'_5#y2L"F4Q8z\n\xec]/'

app = Flask(__name__)
app.config.from_object(__name__)
app.config.from_envvar('MINITWIT_SETTINGS', silent=True)


def query_db(query, args=(), one=False):
    """Queries the database and returns a list of dictionaries."""
    db = cluster.connect(KEYSPACE)

    cur = get_db().execute(query, args)
    rv = cur.fetchall()
    return (rv[0] if rv else None) if one else rv

def get_db():
    """Opens a new database connection if there is none yet for the
    current application context.
    """
    top = _app_ctx_stack.top
    if not hasattr(top, 'userdata_db'):
        top.userdata_db = cluster.connect(KEYSPACE)
        top.userdata_db.row_factory = dict_factory
    return top.userdata_db


@app.teardown_appcontext
def close_database(exception):
    """Closes the database again at the end of the request."""
    top = _app_ctx_stack.top
    if hasattr(top, 'userdata_db'):
        top.userdata_db.close()


@app.cli.command('initdb')
def initdb_command():
    """Creates the database tables."""
    init_db()
    print('Initialized the database.')


@app.cli.command('populatedb')
def populatedb_command():
    """Inputs data in database tables."""
    populate_db()
    print('Database population is completed.')

def populate_db():
    #Populates the database.
    #db = get_db()
    db = cluster.connect(KEYSPACE)
    db.execute('USE userdata')

    db.execute("""INSERT INTO user(username, user_id, email, pw_hash) VALUES ('mark', uuid(), 'mark@sample.com', 'pbkdf2:sha256:50000$ohqiElyi$252bad2e576361a8e6b030ef11118ef44cecaa73a89d6261e4c264acd77fb20b' );""")
    db.execute("""INSERT INTO user(username, user_id, email, pw_hash) VALUES ('john', uuid(), 'john@sample.com', 'pbkdf2:sha256:50000$T4VE9mTh$a98e6153057717e6d1580614b0e4e10349d2c4fded64fd234ad7f7039cf2367e' );""")
    db.execute("""INSERT INTO user(username, user_id, email, pw_hash) VALUES ('tom', uuid(), 'tom@sample.com', 'pbkdf2:sha256:50000$MtSnA8fD$00a15a4360be3ae035f16612290bfc96badc567f4d3ebb678f3b3a1827ffcd35' );""")
    db.execute("""INSERT INTO user(username, user_id, email, pw_hash) VALUES ('jack', uuid(), 'jack@sample.com', 'pbkdf2:sha256:50000$0ujvulkd$c3e82bc1beaae9f8bab74b468c012f7642e36da764d2f64d332325819df3ecea' );""")
    db.execute("""INSERT INTO user(username, user_id, email, pw_hash) VALUES ('craig', uuid(), 'craig@sample.com', 'pbkdf2:sha256:50000$tQ3v5Fmy$77377f7f0740cc1b836332e7862d6cf0d97b54f9fc84ed01c76c483d03934a50' );""")
    db.execute("""INSERT INTO user(username, user_id, email, pw_hash) VALUES ('josh', uuid(), 'josh@sample.com', 'pbkdf2:sha256:50000$0fKZMC5m$b4c3e62978d7f75cc6c112e1937e17ce9fa28cbfed1f484e7063732dd0ad8127' );""")
    db.execute("""INSERT INTO user(username, user_id, email, pw_hash) VALUES ('bilbo', uuid(), 'bilbo@sample.com', 'pbkdf2:sha256:50000$FCV2OQCj$e4c87d8752b5b9ce1b5d97aa70dbd4f9cd16d0caaefcf7d3886a928229388d62' );""")
    db.execute("""INSERT INTO user(username, user_id, email, pw_hash) VALUES ('legolas', 35fc7f24-09f5-49de-9072-506cb96c8411, 'legolas@sample.com', 'pbkdf2:sha256:50000$e3VqTFfu$0a35b8a050ecbe697fdd1cc8e53314e31f20a6a15148d1476f0e92fedf32d271' );""")
    db.execute("""INSERT INTO user(username, user_id, email, pw_hash) VALUES ('banksy', uuid(), 'banksy@sample.com', 'pbkdf2:sha256:50000$k6Iwq6G3$72c3815cfa3de747cefddab822ca7650fa805205585e2395f77ec5e08f75f2ce' );""")
    db.execute("""INSERT INTO user(username, user_id, email, pw_hash) VALUES ('drake', uuid(), 'drake@sample.com', 'pbkdf2:sha256:50000$QidHeH0b$a5cfa1f068c2d162bd7cf82662f90db5f87e31a830ca1e953b1e6d0707f32e82' );""")

    db.execute("""INSERT INTO message(author_id, username, pub_date, email, text) VALUES
    (35fc7f24-09f5-49de-9072-506cb96c8411, 'legolas', 1518739148, 'legolas@example.com', 'hello minitwit!',)""")

    db.execute("""INSERT INTO follower(who_id, whom_id) VALUES
    (3bc16f4a-ee55-4a14-b7d4-fd96c4ca9e22, {35fc7f24-09f5-49de-9072-506cb96c8411}); """)
    db.execute("""INSERT INTO follower(who_id, whom_id) VALUES
    (b3a0a35b-850d-436b-bb62-ab5a54d16f32, {3bc16f4a-ee55-4a14-b7d4-fd96c4ca9e22, 35fc7f24-09f5-49de-9072-506cb96c8411});""")
    db.execute("""INSERT INTO follower(who_id, whom_id) VALUES
    (a7e8c623-1547-42cd-b0ea-7fb220835ec4, {b3a0a35b-850d-436b-bb62-ab5a54d16f32, 0bb3e74c-a2cc-4a93-b38e-99d2f8109e05, 76ee3c8a-b513-487a-898f-13046d257686});""")
    db.execute("""INSERT INTO follower(who_id, whom_id) VALUES
    (0359dfd6-1965-4e1a-ba4e-1eb740fd5f98, {0bb3e74c-a2cc-4a93-b38e-99d2f8109e05});""")
    db.execute("""INSERT INTO follower(who_id, whom_id) VALUES
    (1b9f0f18-cfef-4037-b9e9-19561fd7e171, {0359dfd6-1965-4e1a-ba4e-1eb740fd5f98, 35fc7f24-09f5-49de-9072-506cb96c8411});""")

    #db.execute("cqlsh -f population.cql");


def init_db():
    """Initializes the database."""
    db = cluster.connect()

    """Create Keypsace"""
    db.execute("drop keyspace if exists userdata;")

    db.execute("""
    create keyspace userdata
      WITH replication = {
        'class' : 'SimpleStrategy',
        'replication_factor' : 1
    };
    """)

    db.execute("USE userdata;")

    """Create user table"""
    db.execute("drop table if exists userdata.user;");

    db.execute("""
    create table user (
      username text,
      user_id uuid,
      email text,
      pw_hash text,
      PRIMARY KEY (username, user_id)
    );
    """)


    """Create message table"""
    db.execute("drop table if exists userdata.message;")

    db.execute("""
    create table message (
      author_id uuid,
      username text,
      pub_date int,
      email text,
      text text,
      PRIMARY KEY((author_id, username), pub_date)
    );
    """)
    #db.execute("cqlsh -f schema.cql");

class DatabaseAuth(BasicAuth):
    def __init__(self, app):
		BasicAuth.__init__(self, app)

    def check_credentials(self, username, password):
        print 'Checking %s - %s' % (username, password)
		# look up username in DB
        db = cluster.connect('userdata')

        user = db.execute('select * from user where username = ?', [username], one=True)
        if user is None:
            abort(make_response(jsonify(message="User does not exist"),401))

        if user['username'] == username and check_password_hash(user['pw_hash'], password):
		    # return True if hashed password matches password from DB
            g.user = db.execute('select * from user where username = ?',[username], one=True)
            return True
        else:
            return False

auth = DatabaseAuth(app)

"""Error messages Jsonified"""
@app.errorhandler(400)
def bad_request(error):
    return make_response(jsonify({'error': 'Bad Request'}), 400)

@app.errorhandler(401)
def unauthorized(error):
    return make_response(jsonify({'error': 'Unauthorized access. Incorrect email and address entered'}), 401)

@app.errorhandler(404)
def not_found(error):
    return make_response(jsonify({'error': 'Not found'}), 404)

@app.errorhandler(405)
def method_not_allowed(error):
    return make_response(jsonify({'error': 'Method not allowed'}, 405))

def get_user_id(username):
    """Convenience method to look up the id for a username."""
    db = cluster.connect(KEYSPACE)
    rv = db.execute('select user_id from user where username = ?',
                  [username], one=True)
    return rv[0] if rv else None

def get_user_name(user_id):
    """Convenience method to look up the id for a username."""
    db = cluster.connect(KEYSPACE)
    rv = db.execute('select username from user where user_id = ?',
                  [user_id], one=True)
    return rv[0] if rv else None


#added this for the timeline page to check if current user is following
#the user of the current profile being viewed
@app.route('/followed/<user_id>/<profile_id>', methods=['GET', 'POST'])
def followed(user_id, profile_id):
    db = cluster.connect(KEYSPACE)

    json_object = request.get_json()
    followed = db.execute('''select 1 from follower where
        follower.who_id = ? and follower.whom_id = ?''',
        [json_object['user_id'], json_object['profile_id']], one=True) is not None

    return jsonify(followed)


#helper functions that grab the user's info by user_id or username
@app.route('/user_info/<user_id>', methods=['GET', 'POST'])
def user_info(user_id):
    db = cluster.connect(KEYSPACE)

    json_object = request.get_json()
    user = db.execute('select * from user where user_id = ?', [json_object['user_id']], one=True)
    if user is None:
        abort(404)
    user = dict(user)
    return jsonify(user);

@app.route('/confirm_username/<username>', methods=['GET', 'POST'])
def confirm_username(username):
    db = cluster.connect(KEYSPACE)
    json_object = request.get_json()
    user = db.execute('select * from user where username = ?', [json_object['username']], one=True)
    if user is None:
        abort(404)

    user = dict(user)

    return jsonify(user);

@app.route('/posts/public', methods=['GET'])
def public_thread():
    '''Returns all the posted msgs of all users'''
    db = cluster.connect(KEYSPACE)
    msg = db.execute('''select author_id, username, email, text from userdata.message limit ?''', [PER_PAGE])
    msg = map(dict, msg)
    return jsonify(msg)


@app.route('/home', methods=['GET'])
def home_timeline():
    """Shows feed of the current user and all the user is following. If no user is logged in, redirect to public page"""
    db = cluster.connect(KEYSPACE)
    json_object = request.get_json()

    msg = db.execute('''select message.*, user.user_id, user.username, user.email from message, user
        where message.author_id = user.user_id and (user.user_id = ? or user.user_id in (select whom_id from follower
                                where who_id = ?)) order by message.pub_date desc limit ?''',
                                [json_object['user_id'], json_object['user_id'], PER_PAGE])
    msg = map(dict, msg)

    return jsonify(msg)


@app.route('/posts/<username>', methods=['GET'])
def user_timeline(username):
    """Returns the messages/posts of a specific user"""

    if(len(username) == 0):
        abort(404)
    #if not g.user:
	#	abort(401)
    json_object = request.get_json()
    uid = get_user_id(json_object['username'])

    db = cluster.connect(KEYSPACE)
    messages = db.execute('''select author_id, username, email, text from userdata.message where user_id = ? limit ?''', [uid, PER_PAGE])

    msg = map(dict, messages)

    return jsonify(msg)

@app.route('/<username>/follow', methods=['PUT', 'POST', 'GET'])
@auth.required
def follow_user(username):
    '''sets the current user(username) to follow new user (uid)'''
    if(len(username) == 0):
        abort(404)
    if not g.user:
		abort(401)
    if request.method == "POST":
        if(not request.json):
            abort(405)

    json_object = request.get_json()

    whom_id = get_user_id(json_object['profile_user'])
    if whom_id is None:
		abort(404)

    who_id = json_object['current_user']
    if who_id is None:
    	abort(404)

    db = cluster.connect(KEYSPACE)
    db.execute('insert into follower (who_id, whom_id) values (?, ?)', [who_id,whom_id])


    return jsonify(json_object)

@app.route('/<username>/unfollow', methods=['DELETE', 'GET'])
@auth.required
def unfollow_user(username):
    """Removes the current user as a follower of the given username parameter."""
    if not g.user:
        abort(401)

    if request.method == "DELETE":
       if(not request.json):
            abort(400)

    json_object = request.get_json()
    whom_id = get_user_id(json_object['profile_user'])
    if whom_id is None:
        abort(404)

    who_id = json_object['current_user']
    if who_id is None:
        abort(404)

    db = cluster.connect(KEYSPACE)
    db.execute('delete from follower where who_id=? and whom_id=?',
              [who_id, whom_id])

    return jsonify(json_object)


@app.route('/post_message', methods=['POST', 'GET'])
@auth.required
def post_message():
    """registers a new post/message for current user."""
    if not g.user:
		abort(401)
    if request.method == "POST":
        if(not request.json):
            abort(400)

        json_object = request.get_json()
        text = json_object['text']

        db = cluster.connect(KEYSPACE)
        db.execute('''insert into message (author_id, username, email,  pub_date, text,) values (?, ?, ?)''', [json_object['user_id'], json_object['username'], json_object['email'], int(time.time()), text])

        return jsonify(json_object)

@app.route('/register', methods=['POST', 'GET'])
def register():
    if request.method == 'POST':
        if(not request.json):
            abort(405)

        data = request.get_json()

        if not data["username"] or not data["password"] or not data["email"] or not data["password2"]:
            abort(make_response(jsonify({'Error': "Please enter correct information"}), 402))
        elif data["password"] != data["password2"]:
            abort(make_response(jsonify({'Error': "Passwords need to match"}), 402))
        else:
            '''check for duplicate user'''
            if get_user_id(data["username"]) is not None:
                abort(make_response(jsonify({'Error': "User already exists"}), 406))
            else:
                db = cluster.connect(KEYSPACE)
                password = generate_password_hash(data['password'])
                db.execute('''insert into user (username, email, pw_hash) values (?, ?, ?, ?)'''
                ,[data['username'], uuid(), data['email'], password])
                db.commit()
                return jsonify({'username': data['username'], 'email': data['email'], 'status': 'Successfully registered.', 'status code':201})


if __name__ == '__main__':
    app.run(debug=True)
