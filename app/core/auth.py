from flask import Blueprint, render_template, request, flash, redirect, url_for, session
from flask_login import login_user, logout_user, current_user, login_required
from werkzeug.security import check_password_hash
from app.core.models import User

auth_bp = Blueprint('auth', __name__)

@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    # (login view implementation)
    def login():
      if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        
        # Allow admin login even if not active (emergency override)
        if user and user.role == 'admin':
            if check_password_hash(user.password_hash, password):
                session.update(user_id=user.id, role=user.role, username=user.username)
                flash('Admin login successful', 'success')
                return redirect(url_for('dashboard_admin'))
        
        # Normal user validation
        if not user or not check_password_hash(user.password_hash, password):
            flash('Invalid credentials','danger')
            return redirect(url_for('login'))
        if not user.is_active:
            flash('Account pending approval','warning')
            return redirect(url_for('login'))
        
        session.update(user_id=user.id, role=user.role, username=user.username)
        flash('Login successful','success')
        return redirect(url_for(f'dashboard_{user.role}'))
    return render_template('login.html')


    


@auth_bp.route('/logout')
@login_required
def logout():
    # ... (logout implementation)
    session.clear()
    flash('Logged out', 'info')
    return redirect(url_for('login'))
  
# ... (authentication utility functions)