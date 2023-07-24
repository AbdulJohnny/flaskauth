from flask import Flask, render_template, url_for, request, jsonify, redirect, flash, session
from flask_login import LoginManager, login_user, logout_user, login_required, current_user, UserMixin
from wtforms import Form, StringField, PasswordField, RadioField
from wtforms.validators import DataRequired, Email
import mysql.connector
from passlib.hash import sha256_crypt
import secrets

app = Flask(__name__)
app.config['SECRET_KEY'] = 'd5fb8c4fa8bd46638dadc4e751e0d68d'
login_manager = LoginManager(app)
login_manager.init_app(app)
login_manager.login_view = 'login'

app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = ''
app.config['MYSQL_DB'] = 'flask_db_test'

conn = mysql.connector.connect(
    host=app.config['MYSQL_HOST'],
    user=app.config['MYSQL_USER'],
    password=app.config['MYSQL_PASSWORD'],
    database=app.config['MYSQL_DB']
)

cursor = conn.cursor()

class User(UserMixin):
    def __init__(self, user_id):
        self.id = user_id
        self.name = None
        self.email = None
        self.password_hash = None
        self.role = None

class LoginForm(Form):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])

class AdminUserEditForm(Form):
    username = StringField('Username', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    role = RadioField('Role', choices=[('admin', 'Admin'), ('reporter', 'Reporter'), ('analyst', 'Analyst')], validators=[DataRequired()])

class UserEditForm(Form):
    username = StringField('Username', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])

@login_manager.user_loader
def load_user(user_id):
    cursor = conn.cursor()
    query = "SELECT id, Name, Email, Role FROM Users WHERE id = %s"
    cursor.execute(query, (user_id,))
    result = cursor.fetchone()
    cursor.close()

    if result:
        user = User(result[0])
        user.name = result[1]
        user.email = result[2]
        user.role = result[3]
        return user

    return None

@app.route('/dashboard', methods=['POST', 'GET'])
@login_required
def dashboard():
    if current_user.role == 'admin':
        return render_template('admin_dashboard.html')
    else:
        return render_template('user_dashboard.html')

@app.route('/')
def home():
    return render_template('home.html')

@app.route('/login', methods=['POST'])
def api_login():
    email = request.form['email']
    password = request.form['password']

    cursor = conn.cursor()
    query = "SELECT id, Name, Email, Password FROM Users WHERE Email = %s"
    cursor.execute(query, (email,))
    result = cursor.fetchone()
    cursor.close()

    if result:
        user_id, name, _, hashed_password = result
        if sha256_crypt.verify(password, hashed_password):
            user = User(user_id)
            user.name = name
            login_user(user)
            flash('You have been logged in!', 'success')
            return redirect(url_for('dashboard'))

    flash('Invalid email or password', 'error')
    return redirect(url_for('login'))


@app.route('/login', methods=['GET'])
def login():
    form = LoginForm()
    return render_template('login.html', form=form)

@app.route('/logout', methods=['POST', 'GET'])
@login_required
def logout():
    logout_user()
    session.clear()
    flash('Successfully Logged Out')
    return redirect(url_for('home'))


@app.route('/admin/dashboard', methods=['GET'])
@login_required
def admin_dashboard():
    if current_user.role == 'admin':
        return render_template('admin_dashboard.html')
    else:
        flash('You are not authorized to access this page!', 'error')
        return redirect(url_for('dashboard'))


@app.route('/admin/view_users', methods=['GET'])
@login_required
def view_users():
    if current_user.role == 'admin':
        cursor = conn.cursor()
        query = "SELECT id, Name, Email, Role FROM Users"
        cursor.execute(query)
        users = cursor.fetchall()
        cursor.close()
        return render_template('view_users.html', users=users)
    else:
        flash('You are not authorized to access this page!', 'error')
        return redirect(url_for('dashboard'))

@app.route('/edit_profile', methods=['GET', 'POST'])
@login_required
def edit_profile():
    form = UserEditForm(request.form, obj=current_user)
    if request.method == 'POST' and form.validate():
        username = form.username.data
        email = form.email.data
        password = form.password.data

        try:
            if password:  # If password field is not empty, update the password
                hashed_password = sha256_crypt.hash(password)
                cursor = conn.cursor()
                query = "UPDATE Users SET Name = %s, Email = %s, Password = %s WHERE id = %s"
                values = (username, email, hashed_password, current_user.id)
            else:
                cursor = conn.cursor()
                query = "UPDATE Users SET Name = %s, Email = %s WHERE id = %s"
                values = (username, email, current_user.id)
            cursor.execute(query, values)
            conn.commit()
            cursor.close()
            flash('Profile updated successfully', 'success')
            return redirect(url_for('dashboard'))
        except Exception as e:
            print("Error occurred:", str(e))
            flash('Error occurred while updating profile', 'error')

    return render_template('edit_profile.html', form=form)

@app.route('/admin/add_user', methods=['GET', 'POST'])
@login_required
def add_user():
    if current_user.role == 'admin':
        form = AdminUserEditForm(request.form)
        if request.method == 'POST' and form.validate():
            username = form.username.data
            email = form.email.data
            role = form.role.data

            try:
                hashed_password = sha256_crypt.hash(secrets.token_hex(16))  # Generate a random password for new users

                cursor = conn.cursor()
                query = "INSERT INTO Users (Name, Email, Password, Role) VALUES (%s, %s, %s, %s)"
                values = (username, email, hashed_password, role)
                cursor.execute(query, values)
                conn.commit()
                cursor.close()
                flash('User added successfully', 'success')
                return redirect(url_for('view_users'))
            except Exception as e:
                print("Error occurred:", str(e))
                flash('Error occurred while adding user', 'error')
        return render_template('add_user.html', form=form)
    else:
        flash('You are not authorized to access this page!', 'error')
        return redirect(url_for('dashboard'))

@app.route('/admin/edit_user/<int:user_id>', methods=['GET', 'POST'])
@login_required
def admin_edit_user(user_id):
    if current_user.role == 'admin':
        cursor = conn.cursor()
        query = "SELECT id, Name, Email, Role FROM Users WHERE id = %s"
        cursor.execute(query, (user_id,))
        user = cursor.fetchone()
        cursor.close()

        if user:
            form = AdminUserEditForm(request.form, obj=user)
            if request.method == 'POST' and form.validate():
                username = form.username.data
                email = form.email.data
                password = form.password.data
                role = form.role.data

                try:
                    if password:  # If password field is not empty, update the password
                        hashed_password = sha256_crypt.hash(password)
                        cursor = conn.cursor()
                        query = "UPDATE Users SET Name = %s, Email = %s, Password = %s, Role = %s WHERE id = %s"
                        values = (username, email, hashed_password, role, user_id)
                    else:
                        cursor = conn.cursor()
                        query = "UPDATE Users SET Name = %s, Email = %s, Role = %s WHERE id = %s"
                        values = (username, email, role, user_id)

                    cursor.execute(query, values)
                    conn.commit()
                    cursor.close()
                    flash('User profile updated successfully', 'success')
                    return redirect(url_for('view_users'))
                except Exception as e:
                    print("Error occurred:", str(e))
                    flash('Error occurred while updating user profile', 'error')

            return render_template('admin_edit_profile.html', form=form)
        else:
            flash('User not found', 'error')
            return redirect(url_for('view_users'))
    else:
        flash('You are not authorized to access this page!', 'error')
        return redirect(url_for('dashboard'))

@app.route('/admin/delete_user/<int:user_id>', methods=['POST'])
@login_required
def delete_user(user_id):
    if current_user.role == 'admin':
        cursor = conn.cursor()
        query = "DELETE FROM Users WHERE id = %s"
        cursor.execute(query, (user_id,))
        conn.commit()
        cursor.close()
        flash('User deleted successfully', 'success')
    else:
        flash('You are not authorized to perform this action!', 'error')
    return redirect(url_for('view_users'))

if __name__ == '__main__':
    app.run(debug=True)
