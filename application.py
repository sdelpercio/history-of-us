import os
import sqlite3

from cs50 import SQL
from flask import Flask, flash, jsonify, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required

# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True

# Ensure responses aren't cached
@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure SQLite database, ***use cursor.execute() to make changes***
db = SQL("sqlite:///mydatabase.db")


@app.route("/splash", methods=["GET"])
def splash():

    return render_template("splash.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = :username",
                          username=request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@app.route("/register", methods=["GET", "POST"])
def register():

    # Function to check if username has been taken
    def checkname(name):
        users = db.execute("SELECT username FROM users")

        for user in users:
            if user["username"] == name:
                return True
        return False

    inputName = request.form.get("username")
    inputPass = request.form.get("password")
    inputConf = request.form.get("confirmation")

    if request.method == "POST":
        # Ensure username is not blank or a repeat
        if inputName == None:
            return apology("must input a username", 400)
        if checkname(inputName) == True:
            return apology("username has been taken", 400)

        # Ensure password is not blank or dooes not match confirmation
        if inputPass == None:
            return apology("must input a password", 400)
        if inputPass != inputConf:
            return apology("passwords do not match", 400)

        # Store the users' username and password
        hashedPass = generate_password_hash(request.form.get("password"))

        db.execute("INSERT INTO users (username, hash) VALUES (?, ?)", (inputName, hashedPass))

        rows = db.execute("SELECT * FROM users WHERE username = :username",
                      username=inputName)

        # log user and return to index page
        session["user_id"] = rows[0]["id"]
        return redirect("/")

    else:
        return render_template("register.html")


@app.route("/check", methods=["GET"])
def check():

    # get username from get request and find users
    username = request.args.get("username")
    users = db.execute("SELECT * FROM users WHERE username = :username", username = username)

    # check to see if username exists and is atleast length 1 or more
    if len(username) < 1 or len(users) > 0:
        return jsonify(False)
    else:
        return jsonify(True)


@app.route("/add", methods=["POST"])
def add():

    # get information from post
    message = request.form['message']
    lat = request.form['lat']
    lng = request.form['lng']

    # add message information into database
    db.execute("INSERT INTO history (message, lng, lat) VALUES (?, ?, ?)", (message, lng, lat))

    return redirect("/")


@app.route("/")
@login_required
def index():

    # search for all previously made markers
    markers = db.execute("SELECT * FROM history")

    # if blank, load with no markers
    if markers == None:
        return render_template("index.html")

    # else, load map with markers
    return render_template("index.html", markers=markers)


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")


def errorhandler(e):
    """Handle error"""
    if not isinstance(e, HTTPException):
        e = InternalServerError()
    return apology(e.name, e.code)


# Listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)
