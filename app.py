"""
Network Attack Log Monitoring System
Integrated Cybersecurity Monitoring Web Application
"""

from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, Response
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from datetime import datetime, timedelta
import csv
import io
import random
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = 'network-monitor-secret-key-2024'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///network_monitor.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# ==================== DATABASE MODELS ====================

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)

class AttackLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    ip_address = db.Column(db.String(50), nullable=False)
    attack_type = db.Column(db.String(100), nullable=False)
    attempts = db.Column(db.Integer, default=1)
    severity = db.Column(db.String(20), nullable=False)  # Low, Medium, High
    date = db.Column(db.DateTime, default=datetime.now)
    status = db.Column(db.String(20), default='Detected')  # Detected, Blocked

class BlockedIP(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    ip_address = db.Column(db.String(50), unique=True, nullable=False)
    reason = db.Column(db.String(200), nullable=False)
    date_blocked = db.Column(db.DateTime, default=datetime.now)

class Alert(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    message = db.Column(db.Text, nullable=False)
    level = db.Column(db.String(20), nullable=False)  # Low, Medium, High
    date = db.Column(db.DateTime, default=datetime.now)
    is_read = db.Column(db.Boolean, default=False)

# ==================== UTILITY FUNCTIONS ====================

def get_client_ip():
    """Get client IP address from request"""
    if request.headers.get('X-Forwarded-For'):
        return request.headers.get('X-Forwarded-For').split(',')[0]
    return request.remote_addr or '127.0.0.1'

def detect_attack(ip_address, attack_type):
    """Detect attack and take appropriate action"""
    # Check if IP is already blocked
    blocked = BlockedIP.query.filter_by(ip_address=ip_address).first()
    if blocked:
        return False, "IP is blocked"
    
    # Check recent attacks from this IP
    recent_attacks = AttackLog.query.filter(
        AttackLog.ip_address == ip_address,
        AttackLog.date > datetime.now() - timedelta(minutes=10)
    ).count()
    
    total_attempts = recent_attacks + 1
    
    # Determine severity based on attempts
    if total_attempts >= 10:
        severity = 'High'
    elif total_attempts >= 5:
        severity = 'Medium'
    else:
        severity = 'Low'
    
    # Log the attack
    new_attack = AttackLog(
        ip_address=ip_address,
        attack_type=attack_type,
        attempts=1,
        severity=severity,
        status='Detected'
    )
    db.session.add(new_attack)
    
# Auto-block suspicious attacks on first detection
    suspicious_attacks = ['Brute Force Attack', 'SQL Injection Attempt', 'XSS Attack Attempt', 'DDoS Attack Simulation']
    if attack_type in suspicious_attacks:
        block_ip(ip_address, f"Suspicious attack detected: {attack_type}")
        new_attack.status = 'Blocked'
        severity = 'High'
    elif total_attempts >= 10:
        block_ip(ip_address, f"Automatic block: {total_attempts} {attack_type} attempts in last 10 minutes")
        new_attack.status = 'Blocked'
    
    # Create alert for Medium+ severity
    if severity in ['Medium', 'High']:
        alert_level = 'CRITICAL' if severity == 'High' else 'SECURITY'
        alert = Alert(
            message=f"🚨 {alert_level} Alert: {severity} {attack_type} from {ip_address}\\nAttempts: {total_attempts} (last 10min)\\nTime: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            level=severity
        )
        db.session.add(alert)
    
    db.session.commit()
    return True, "Attack logged"

def block_ip(ip_address, reason):
    """Block an IP address"""
    existing = BlockedIP.query.filter_by(ip_address=ip_address).first()
    if not existing:
        blocked = BlockedIP(ip_address=ip_address, reason=reason)
        db.session.add(blocked)
        db.session.commit()
        return True
    return False

def unblock_ip(ip_address):
    """Unblock an IP address"""
    blocked = BlockedIP.query.filter_by(ip_address=ip_address).first()
    if blocked:
        db.session.delete(blocked)
        db.session.commit()
        return True
    return False

# ==================== ROUTES ====================

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        client_ip = get_client_ip()
        
        # Check if IP is blocked
        blocked = BlockedIP.query.filter_by(ip_address=client_ip).first()
        if blocked:
            flash(f'Your IP ({client_ip}) is blocked. Reason: {blocked.reason}', 'danger')
            return render_template('login.html')
        
        user = User.query.filter_by(username=username).first()
        
        if user and user.password == password:
            # Successful login
            login_user(user)
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard'))
        else:
            # Failed login - log as attack
            detect_attack(client_ip, 'Failed Login Attempt')
            flash('Invalid credentials. Failed login attempt logged.', 'danger')
    
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    # Get statistics
    today = datetime.now().date()
    total_attacks_today = AttackLog.query.filter(db.func.date(AttackLog.date) == today).count()
    blocked_ips_count = BlockedIP.query.count()
    high_severity_today = AttackLog.query.filter(
        db.func.date(AttackLog.date) == today,
        AttackLog.severity == 'High'
    ).count()
    
    # Recent attacks (last 10)
    recent_attacks = AttackLog.query.order_by(AttackLog.date.desc()).limit(10).all()
    
    # Recent alerts
    recent_alerts = Alert.query.order_by(Alert.date.desc()).limit(5).all()
    
    # Attack type statistics for chart
    attack_types_query = db.session.query(
        AttackLog.attack_type,
        db.func.count(AttackLog.id)
    ).group_by(AttackLog.attack_type).all()
    attack_types = [[at[0], at[1]] for at in attack_types_query]
    
    return render_template('dashboard.html',
                         total_attacks_today=total_attacks_today,
                         blocked_ips_count=blocked_ips_count,
                         high_severity_today=high_severity_today,
                         recent_attacks=recent_attacks,
                         recent_alerts=recent_alerts,
                         attack_types=attack_types)

@app.route('/api/dashboard-data')
@login_required
def api_dashboard_data():
    """API endpoint for live dashboard updates"""
    today = datetime.now().date()
    
    total_attacks_today = AttackLog.query.filter(db.func.date(AttackLog.date) == today).count()
    blocked_ips_count = BlockedIP.query.count()
    high_severity_today = AttackLog.query.filter(
        db.func.date(AttackLog.date) == today,
        AttackLog.severity == 'High'
    ).count()
    
    recent_attacks = AttackLog.query.order_by(AttackLog.date.desc()).limit(10).all()
    recent_alerts = Alert.query.order_by(Alert.date.desc()).limit(5).all()
    
    attack_types = db.session.query(
        AttackLog.attack_type,
        db.func.count(AttackLog.id)
    ).group_by(AttackLog.attack_type).all()
    
    return jsonify({
        'total_attacks_today': total_attacks_today,
        'blocked_ips_count': blocked_ips_count,
        'high_severity_today': high_severity_today,
        'recent_attacks': [{
            'id': a.id,
            'ip_address': a.ip_address,
            'attack_type': a.attack_type,
            'severity': a.severity,
            'status': a.status,
            'date': a.date.strftime('%Y-%m-%d %H:%M:%S')
        } for a in recent_attacks],
        'recent_alerts': [{
            'id': a.id,
            'message': a.message,
            'level': a.level,
            'date': a.date.strftime('%Y-%m-%d %H:%M:%S')
        } for a in recent_alerts],
        'attack_types': [{'type': a[0], 'count': a[1]} for a in attack_types]
    })

@app.route('/api/alerts-count')
@login_required
def api_alerts_count():
    unread_count = Alert.query.filter_by(is_read=False).count()
    return jsonify({'unread_count': unread_count})

@app.route('/attack-logs')
@login_required
def attack_logs():
    # Get filter parameters
    search_ip = request.args.get('ip', '')
    search_type = request.args.get('type', '')
    search_severity = request.args.get('severity', '')
    
    query = AttackLog.query
    
    if search_ip:
        query = query.filter(AttackLog.ip_address.like(f'%{search_ip}%'))
    if search_type:
        query = query.filter(AttackLog.attack_type == search_type)
    if search_severity:
        query = query.filter(AttackLog.severity == search_severity)
    
    logs = query.order_by(AttackLog.date.desc()).all()
    
    # Get unique attack types for filter
    attack_types = db.session.query(AttackLog.attack_type).distinct().all()
    
    return render_template('attack_logs.html', 
                         logs=logs, 
                         attack_types=[a[0] for a in attack_types],
                         search_ip=search_ip,
                         search_type=search_type,
                         search_severity=search_severity)

@app.route('/blocked-ips')
@login_required
def blocked_ips():
    blocked = BlockedIP.query.order_by(BlockedIP.date_blocked.desc()).all()
    return render_template('blocked_ips.html', blocked_ips=blocked)

@app.route('/unblock-ip/<ip>')
@login_required
def unblock_ip_route(ip):
    if unblock_ip(ip):
        flash(f'IP {ip} has been unblocked.', 'success')
    else:
        flash(f'IP {ip} not found in blocked list.', 'danger')
    return redirect(url_for('blocked_ips'))

@app.route('/reports')
@login_required
def reports():
    # Monthly report data
    now = datetime.now()
    month_start = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    
    if month_start.month == 1:
        month_start = month_start.replace(year=month_start.year - 1, month=12)
    else:
        month_start = month_start.replace(month=month_start.month - 1)
    
    # Current month stats
    current_month_attacks = AttackLog.query.filter(
        AttackLog.date >= month_start
    ).all()
    
    total_attacks = len(current_month_attacks)
    
    # Attack type frequency
    attack_type_freq = {}
    for attack in current_month_attacks:
        attack_type_freq[attack.attack_type] = attack_type_freq.get(attack.attack_type, 0) + 1
    
    # Top attacking IPs
    ip_freq = {}
    for attack in current_month_attacks:
        ip_freq[attack.ip_address] = ip_freq.get(attack.ip_address, 0) + 1
    
    top_ips = sorted(ip_freq.items(), key=lambda x: x[1], reverse=True)[:10]
    
    blocked_count = BlockedIP.query.filter(BlockedIP.date_blocked >= month_start).count()
    
    return render_template('reports.html',
                         total_attacks=total_attacks,
                         attack_type_freq=attack_type_freq,
                         top_ips=top_ips,
                         blocked_count=blocked_count,
                         month=month_start.strftime('%B %Y'))

@app.route('/export-csv')
@login_required
def export_csv():
    """Export attack logs to CSV"""
    logs = AttackLog.query.order_by(AttackLog.date.desc()).all()
    
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['ID', 'IP Address', 'Attack Type', 'Attempts', 'Severity', 'Date', 'Status'])
    
    for log in logs:
        writer.writerow([
            log.id,
            log.ip_address,
            log.attack_type,
            log.attempts,
            log.severity,
            log.date.strftime('%Y-%m-%d %H:%M:%S'),
            log.status
        ])
    
    output.seek(0)
    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={"Content-disposition": "attachment; filename=attack_logs.csv"}
    )

@app.route('/simulation', methods=['GET', 'POST'])
@login_required
def simulation():
    if not current_user.is_admin:
        flash('Access denied. Admin only.', 'danger')
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        sim_type = request.form.get('sim_type')
        target_ip = request.form.get('target_ip', get_client_ip())
        num_attempts = int(request.form.get('num_attempts', 1))
        
        # Map simulation types
        attack_type_map = {
            'brute_force': 'Brute Force Attack',
            'port_scan': 'Port Scan Attempt',
            'ddos': 'DDoS Attack Simulation',
            'sql_injection': 'SQL Injection Attempt',
            'xss': 'XSS Attack Attempt'
        }
        
        attack_type = attack_type_map.get(sim_type, 'Unknown Attack')
        
        # Determine severity
        if num_attempts >= 10:
            severity = 'High'
        elif num_attempts >= 5:
            severity = 'Medium'
        else:
            severity = 'Low'
        
        # Log simulated attacks
        for i in range(num_attempts):
            attack = AttackLog(
                ip_address=target_ip,
                attack_type=attack_type,
                attempts=1,
                severity=severity,
                status='Detected'
            )
            db.session.add(attack)
        
        # Create alert for high severity simulations
        if severity == 'High':
            alert = Alert(
                message=f"⚠ Simulated Attack: High Severity {attack_type}\nIP: {target_ip}\nAttempts: {num_attempts}\nDate: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
                level='High'
            )
            db.session.add(alert)
        
        db.session.commit()
        flash(f'Simulation complete: {num_attempts} {attack_type} attacks simulated from {target_ip}', 'success')
        return redirect(url_for('simulation'))
    
    return render_template('simulation.html')

@app.route('/alerts')
@login_required
def alerts():
    all_alerts = Alert.query.order_by(Alert.date.desc()).all()
    return render_template('alerts.html', alerts=all_alerts)

@app.route('/delete-attack/<int:id>')
@login_required
def delete_attack(id):
    if not current_user.is_admin:
        flash('Access denied. Admin only.', 'danger')
        return redirect(url_for('attack_logs'))
    
    attack = AttackLog.query.get(id)
    if attack:
        db.session.delete(attack)
        db.session.commit()
        flash(f'Attack log #{id} has been deleted.', 'success')
    else:
        flash(f'Attack log #{id} not found.', 'danger')
    return redirect(url_for('attack_logs'))

@app.route('/delete-all-attacks')
@login_required
def delete_all_attacks():
    if not current_user.is_admin:
        flash('Access denied. Admin only.', 'danger')
        return redirect(url_for('attack_logs'))
    
    try:
        db.session.query(AttackLog).delete()
        db.session.commit()
        flash('All attack logs have been deleted.', 'success')
    except:
        db.session.rollback()
        flash('Error deleting attack logs.', 'danger')
    return redirect(url_for('attack_logs'))

@app.route('/delete-alert/<int:id>')
@login_required
def delete_alert(id):
    if not current_user.is_admin:
        flash('Access denied. Admin only.', 'danger')
        return redirect(url_for('alerts'))
    
    alert = Alert.query.get(id)
    if alert:
        db.session.delete(alert)
        db.session.commit()
        flash(f'Alert #{id} has been deleted.', 'success')
    else:
        flash(f'Alert #{id} not found.', 'danger')
    return redirect(url_for('alerts'))

@app.route('/delete-all-alerts')
@login_required
def delete_all_alerts():
    if not current_user.is_admin:
        flash('Access denied. Admin only.', 'danger')
        return redirect(url_for('alerts'))
    
    try:
        db.session.query(Alert).delete()
        db.session.commit()
        flash('All alerts have been deleted.', 'success')
    except:
        db.session.rollback()
        flash('Error deleting alerts.', 'danger')
    return redirect(url_for('alerts'))

# ==================== INITIALIZATION ====================

def init_db():
    """Initialize database with default data"""
    db.create_all()
    
    # Create admin user if not exists
    admin = User.query.filter_by(username='admin').first()
    if not admin:
        admin = User(username='admin', password='admin123', is_admin=True)
        db.session.add(admin)
        
        # Create test user
        test_user = User(username='user', password='user123', is_admin=False)
        db.session.add(test_user)
        
        db.session.commit()
        print("✓ Database initialized with default users (admin/admin123)")

if __name__ == '__main__':
    with app.app_context():
        init_db()
    app.run(debug=True, port=5000)

