import os
import re
from datetime import datetime
from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd

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


# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")

# Make sure API key is set
if not os.environ.get("API_KEY"):
    raise RuntimeError("API_KEY not set")


@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""
    # rows = db.execute("SELECT ")
    # return render_template("index.html")
    cash = db.execute("SELECT cash from users where id = ?", session["user_id"])
    owns = db.execute("SELECT * FROM owns WHERE id = ?", session["user_id"])
    print(owns)
    total = 0
    for share in owns:
        share['price'] = lookup(share['symbol'])['price']
        share['total'] = round(share['price'] * share['shares'], 2)
        share['name'] = lookup(share['symbol'])['name']
        total += share['total']
    cash = round(cash[0]["cash"], 2)
    total += cash
    total = round(total, 2)
    print(owns)
    return render_template("index.html", cash=cash, owns=owns, total=total)


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""
    if request.method == "GET":
        return render_template("buy.html")

    if request.method == "POST":
        symbol = request.form.get("symbol")
        stocks = lookup(symbol)
        if not stocks:
            return apology("INVALID SYMBOL!")

        shares = request.form.get("shares")

        if not shares.isdigit():
            return apology("Shares should be numeric")

        stocks = lookup(symbol)

        price = float(shares) * stocks['price']

        cash = db.execute("SELECT cash from users where id = ?", session["user_id"])
        # cash = ca
        # print(cash[0]['cash'])
        if price > cash[0]['cash']:
            return apology("You don't have enough cash!")

        cash = cash[0]['cash'] - price

        temp = db.execute("UPDATE users SET cash = ? WHERE id = ?", cash, session["user_id"])

        print(temp)

        rows = db.execute("SELECT * FROM users WHERE id = ?", session["user_id"])
        temp = db.execute("INSERT INTO history (id, shares, price, dtime, symbol) VALUES (?, ? , ?, ?, ?)",
                          session['user_id'], shares, price, datetime.now().strftime("%d/%m/%Y %H:%M:%S"), symbol)
        buyed = db.execute("SELECT * FROM owns WHERE symbol = ? AND id = ?", symbol, session['user_id'])
        print("buyed")
        print(buyed)
        print("shares")
        print(str(shares) + str(type(shares)))
        if len(buyed) == 0:
            db.execute("INSERT INTO owns (id, symbol, shares) VALUES (?, ?, ?)", session["user_id"], symbol, shares)
        else:
            k = db.execute("UPDATE owns SET shares = shares + ? WHERE id = ? AND symbol = ?",
                           int(shares), session["user_id"], symbol)
            print(k)
            buyed = db.execute("SELECT * FROM owns WHERE symbol = ? AND id = ?", symbol, session['user_id'])
            print("buyed")
            flash("Buyed!")
        return redirect("/")

    return apology("TODO")


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    hist = db.execute("SELECT * FROM history WHERE id = ?", session['user_id'])
    return render_template("history.html", hist=hist)


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
        rows = db.execute("SELECT * FROM users WHERE username = ?", request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        flash("Successfully Loged In")
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")


@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    """Get stock quote."""
    if request.method == "GET":
        return render_template("quote.html")

    if request.method == "POST":
        symbol = request.form.get("symbol")
        stocks = lookup(symbol)
        print(stocks)
        if not stocks:
            return apology("INVALID SYMBOL!")
        return render_template("quoted.html", stocks=stocks)

    return apology("TODO")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    flash(
        "Your password should be of atleast 8 Characters and should consist atleast one number[0-9], one letter and one of these special characters[$, @ , _]")
    if request.method == "POST":

        username = db.execute("SELECT username from users where username = ?", request.form.get("username"))

        if len(username) == 1:
            return apology("Username already exists")

        if not request.form.get("password") or not request.form.get("confirmation") or not request.form.get("username"):
            return apology("All fields are required!")

        if not request.form.get("password") == request.form.get("confirmation"):
            return apology("Confirmatin password and password do not match")

        password = request.form.get("password")

        # if (len(password) < 8) or not re.search("[a-z]", password) or not re.search("[A-Z]", password) or not re.search("[0-9]", password) or not re.search("[_@$]", password) or re.search("\s", password):
        #     return apology("Password doesn't match the requirements", 403)

        username = request.form.get("username")
        password = generate_password_hash(request.form.get("password"))

        db.execute("INSERT INTO users (username, hash) VALUES (?, ?)", username, password)

        usrid = db.execute("SELECT id from users where username = ?", username)

        session["user_id"] = usrid[0]['id']

        flash("You Successfully registered")

        return redirect("/")

    return render_template("register.html")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""
    symbols = db.execute("SELECT symbol FROM owns WHERE id = ?", session["user_id"])
    print(symbols)

    if request.method == "GET":
        if len(symbols) == 0:
            return apology("You have not buyed any stocks yet!")
        return render_template("sell.html", symbols=symbols)

    if request.method == "POST":
        dShares = request.form.get("shares")
        symbol = request.form.get("symbol")

        aShares = db.execute("SELECT shares FROM owns WHERE id = ? AND symbol = ?", session["user_id"], symbol)
        rows = db.execute("SELECT * FROM users")
        print(aShares, type(aShares))
        print(dShares, type(dShares))

        price = lookup(symbol)['price']

        if int(dShares) > aShares[0]["shares"]:
            return apology("Too many Shares!")

        elif int(dShares) == aShares[0]["shares"]:
            db.execute("DELETE FROM owns WHERE symbol = ? AND id = ?", symbol, session["user_id"])

        else:
            db.execute("UPDATE owns SET shares = shares - ? WHERE symbol = ? AND id = ?", int(dShares), symbol, session["user_id"])

        db.execute("UPDATE users SET cash = cash + ? WHERE id = ?", price * int(dShares), session['user_id'])
        dShares = -int(dShares)
        temp = db.execute("INSERT INTO history (id, shares, price, dtime, symbol) VALUES (?, ? , ?, ?, ?)",
                          session['user_id'], dShares, price, datetime.now().strftime("%d/%m/%Y %H:%M:%S"), symbol)
        flash("Sold!")
        return redirect("/")

        print(aShares)

    return apology("YOU'RE AWESOME")


def errorhandler(e):
    """Handle error"""
    if not isinstance(e, HTTPException):
        e = InternalServerError()
    return apology(e.name, e.code)


# Listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)
