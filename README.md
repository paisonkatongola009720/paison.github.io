"""
Professional Helpdesk Ticketing System
A complete customer support platform with authentication, notifications, and analytics
"""

from flask import Flask, render_template_string, request, redirect, url_for, flash, session, jsonify, send_file
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from datetime import datetime, timedelta
from functools import wraps
import os
import json
import csv
import io
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import logging
import sqlite3
import shutil

# Initialize Flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-change-in-production'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///ticketing_system.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size

# Create uploads folder
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Initialize database
db = SQLAlchemy(app)

# Configure logging
logging.basicConfig(
    filename='ticketing_system.log',
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# ==================== DATABASE MODELS ====================

class User(db.Model):
    """User model for authentication and authorization"""
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(20), nullable=False)  # admin, agent, user
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_active = db.Column(db.Boolean, default=True)
    tickets_created = db.relationship('Ticket', backref='creator', foreign_keys='Ticket.user_id', lazy=True)
    tickets_assigned = db.relationship('Ticket', backref='agent', foreign_keys='Ticket.assigned_to', lazy=True)

class Ticket(db.Model):
    """Ticket model for support requests"""
    id = db.Column(db.Integer, primary_key=True)
    ticket_id = db.Column(db.String(20), unique=True, nullable=False)
    subject = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=False)
    priority = db.Column(db.String(20), nullable=False)  # Low, Medium, High, Critical
    status = db.Column(db.String(20), default='Open')  # Open, In Progress, Resolved, Closed
    category = db.Column(db.String(50), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    assigned_to = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    resolved_at = db.Column(db.DateTime, nullable=True)
    closed_at = db.Column(db.DateTime, nullable=True)
    sla_deadline = db.Column(db.DateTime, nullable=True)
    comments = db.relationship('Comment', backref='ticket', lazy=True, cascade='all, delete-orphan')
    attachments = db.relationship('Attachment', backref='ticket', lazy=True, cascade='all, delete-orphan')
    history = db.relationship('TicketHistory', backref='ticket', lazy=True, cascade='all, delete-orphan')

class Comment(db.Model):
    """Comment model for ticket discussions"""
    id = db.Column(db.Integer, primary_key=True)
    ticket_id = db.Column(db.Integer, db.ForeignKey('ticket.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    content = db.Column(db.Text, nullable=False)
    is_internal = db.Column(db.Boolean, default=False)  # Internal notes for agents
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    user = db.relationship('User', backref='comments')

class Attachment(db.Model):
    """Attachment model for file uploads"""
    id = db.Column(db.Integer, primary_key=True)
    ticket_id = db.Column(db.Integer, db.ForeignKey('ticket.id'), nullable=False)
    filename = db.Column(db.String(200), nullable=False)
    filepath = db.Column(db.String(500), nullable=False)
    uploaded_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    uploaded_at = db.Column(db.DateTime, default=datetime.utcnow)
    user = db.relationship('User', backref='attachments')

class TicketHistory(db.Model):
    """Track all changes to tickets"""
    id = db.Column(db.Integer, primary_key=True)
    ticket_id = db.Column(db.Integer, db.ForeignKey('ticket.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    action = db.Column(db.String(100), nullable=False)
    old_value = db.Column(db.String(200))
    new_value = db.Column(db.String(200))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    user = db.relationship('User', backref='history_entries')

class KnowledgeBase(db.Model):
    """Knowledge base articles for self-service"""
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    content = db.Column(db.Text, nullable=False)
    category = db.Column(db.String(50), nullable=False)
    created_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    views = db.Column(db.Integer, default=0)
    is_published = db.Column(db.Boolean, default=True)
    user = db.relationship('User', backref='kb_articles')

# ==================== HELPER FUNCTIONS ====================

def generate_ticket_id():
    """Generate unique ticket ID"""
    last_ticket = Ticket.query.order_by(Ticket.id.desc()).first()
    if last_ticket:
        num = int(last_ticket.ticket_id.split('-')[1]) + 1
    else:
        num = 1000
    return f"TKT-{num}"

def calculate_sla_deadline(priority):
    """Calculate SLA deadline based on priority"""
    sla_hours = {
        'Critical': 4,
        'High': 24,
        'Medium': 72,
        'Low': 168
    }
    return datetime.utcnow() + timedelta(hours=sla_hours.get(priority, 72))

def send_notification(user_email, subject, message):
    """Send email notification (configure SMTP settings)"""
    try:
        # Note: Configure these settings in production
        # This is a placeholder - you'll need to add your SMTP credentials
        logger.info(f"Notification sent to {user_email}: {subject}")
        return True
    except Exception as e:
        logger.error(f"Failed to send notification: {str(e)}")
        return False

def auto_assign_ticket(ticket):
    """Auto-assign ticket to available agent with least workload"""
    try:
        agents = User.query.filter_by(role='agent', is_active=True).all()
        if not agents:
            return None
        
        # Find agent with least open tickets
        min_tickets = float('inf')
        selected_agent = None
        
        for agent in agents:
            open_tickets = Ticket.query.filter_by(
                assigned_to=agent.id,
                status__in=['Open', 'In Progress']
            ).count()
            
            if open_tickets < min_tickets:
                min_tickets = open_tickets
                selected_agent = agent
        
        return selected_agent
    except Exception as e:
        logger.error(f"Auto-assignment failed: {str(e)}")
        return None

def log_ticket_history(ticket_id, user_id, action, old_value=None, new_value=None):
    """Log ticket history"""
    try:
        history = TicketHistory(
            ticket_id=ticket_id,
            user_id=user_id,
            action=action,
            old_value=old_value,
            new_value=new_value
        )
        db.session.add(history)
        db.session.commit()
    except Exception as e:
        logger.error(f"Failed to log history: {str(e)}")

def login_required(f):
    """Decorator to require login"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page.', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def role_required(*roles):
    """Decorator to require specific role"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if 'user_id' not in session:
                flash('Please log in to access this page.', 'warning')
                return redirect(url_for('login'))
            
            user = User.query.get(session['user_id'])
            if user.role not in roles:
                flash('You do not have permission to access this page.', 'danger')
                return redirect(url_for('dashboard'))
            return f(*args, **kwargs)
        return decorated_function
    return decorator

# ==================== ROUTES ====================

@app.route('/')
def index():
    """Home page"""
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    """User login"""
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        user = User.query.filter_by(username=username).first()
        
        if user and check_password_hash(user.password_hash, password):
            if not user.is_active:
                flash('Your account has been deactivated.', 'danger')
                return redirect(url_for('login'))
            
            session['user_id'] = user.id
            session['username'] = user.username
            session['role'] = user.role
            logger.info(f"User {username} logged in successfully")
            flash(f'Welcome back, {user.username}!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password.', 'danger')
            logger.warning(f"Failed login attempt for username: {username}")
    
    return render_template_string(LOGIN_TEMPLATE)

@app.route('/register', methods=['GET', 'POST'])
def register():
    """User registration"""
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        
        if User.query.filter_by(username=username).first():
            flash('Username already exists.', 'danger')
            return redirect(url_for('register'))
        
        if User.query.filter_by(email=email).first():
            flash('Email already registered.', 'danger')
            return redirect(url_for('register'))
        
        user = User(
            username=username,
            email=email,
            password_hash=generate_password_hash(password),
            role='user'
        )
        db.session.add(user)
        db.session.commit()
        
        logger.info(f"New user registered: {username}")
        flash('Registration successful! Please log in.', 'success')
        return redirect(url_for('login'))
    
    return render_template_string(REGISTER_TEMPLATE)

@app.route('/logout')
def logout():
    """User logout"""
    username = session.get('username', 'Unknown')
    session.clear()
    logger.info(f"User {username} logged out")
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    """Main dashboard"""
    user = User.query.get(session['user_id'])
    
    # Get statistics
    if user.role == 'admin':
        total_tickets = Ticket.query.count()
        open_tickets = Ticket.query.filter_by(status='Open').count()
        in_progress = Ticket.query.filter_by(status='In Progress').count()
        resolved = Ticket.query.filter_by(status='Resolved').count()
        closed = Ticket.query.filter_by(status='Closed').count()
        
        # Calculate average resolution time
        resolved_tickets = Ticket.query.filter(Ticket.resolved_at.isnot(None)).all()
        avg_resolution = 0
        if resolved_tickets:
            total_time = sum([(t.resolved_at - t.created_at).total_seconds() / 3600 
                            for t in resolved_tickets])
            avg_resolution = round(total_time / len(resolved_tickets), 2)
        
        # Agent performance
        agents = User.query.filter_by(role='agent').all()
        agent_stats = []
        for agent in agents:
            agent_tickets = Ticket.query.filter_by(assigned_to=agent.id).count()
            agent_resolved = Ticket.query.filter_by(
                assigned_to=agent.id, 
                status='Resolved'
            ).count()
            agent_stats.append({
                'name': agent.username,
                'total': agent_tickets,
                'resolved': agent_resolved
            })
        
        recent_tickets = Ticket.query.order_by(Ticket.created_at.desc()).limit(10).all()
        
    elif user.role == 'agent':
        total_tickets = Ticket.query.filter_by(assigned_to=user.id).count()
        open_tickets = Ticket.query.filter_by(assigned_to=user.id, status='Open').count()
        in_progress = Ticket.query.filter_by(assigned_to=user.id, status='In Progress').count()
        resolved = Ticket.query.filter_by(assigned_to=user.id, status='Resolved').count()
        closed = Ticket.query.filter_by(assigned_to=user.id, status='Closed').count()
        avg_resolution = 0
        agent_stats = []
        recent_tickets = Ticket.query.filter_by(assigned_to=user.id).order_by(
            Ticket.created_at.desc()
        ).limit(10).all()
    else:
        total_tickets = Ticket.query.filter_by(user_id=user.id).count()
        open_tickets = Ticket.query.filter_by(user_id=user.id, status='Open').count()
        in_progress = Ticket.query.filter_by(user_id=user.id, status='In Progress').count()
        resolved = Ticket.query.filter_by(user_id=user.id, status='Resolved').count()
        closed = Ticket.query.filter_by(user_id=user.id, status='Closed').count()
        avg_resolution = 0
        agent_stats = []
        recent_tickets = Ticket.query.filter_by(user_id=user.id).order_by(
            Ticket.created_at.desc()
        ).limit(10).all()
    
    return render_template_string(DASHBOARD_TEMPLATE, 
        user=user,
        total_tickets=total_tickets,
        open_tickets=open_tickets,
        in_progress=in_progress,
        resolved=resolved,
        closed=closed,
        avg_resolution=avg_resolution,
        agent_stats=agent_stats,
        recent_tickets=recent_tickets
    )

@app.route('/tickets')
@login_required
def tickets():
    """View all tickets"""
    user = User.query.get(session['user_id'])
    
    # Get filter parameters
    status_filter = request.args.get('status', '')
    priority_filter = request.args.get('priority', '')
    search_query = request.args.get('search', '')
    
    # Build query based on user role
    if user.role == 'admin':
        query = Ticket.query
    elif user.role == 'agent':
        query = Ticket.query.filter_by(assigned_to=user.id)
    else:
        query = Ticket.query.filter_by(user_id=user.id)
    
    # Apply filters
    if status_filter:
        query = query.filter_by(status=status_filter)
    if priority_filter:
        query = query.filter_by(priority=priority_filter)
    if search_query:
        query = query.filter(
            (Ticket.subject.contains(search_query)) |
            (Ticket.ticket_id.contains(search_query))
        )
    
    tickets = query.order_by(Ticket.created_at.desc()).all()
    
    return render_template_string(TICKETS_TEMPLATE, 
        user=user,
        tickets=tickets,
        status_filter=status_filter,
        priority_filter=priority_filter,
        search_query=search_query
    )

@app.route('/ticket/create', methods=['GET', 'POST'])
@login_required
def create_ticket():
    """Create new ticket"""
    if request.method == 'POST':
        subject = request.form.get('subject')
        description = request.form.get('description')
        priority = request.form.get('priority')
        category = request.form.get('category')
        
        ticket = Ticket(
            ticket_id=generate_ticket_id(),
            subject=subject,
            description=description,
            priority=priority,
            category=category,
            user_id=session['user_id'],
            sla_deadline=calculate_sla_deadline(priority)
        )
        
        # Auto-assign to agent
        agent = auto_assign_ticket(ticket)
        if agent:
            ticket.assigned_to = agent.id
        
        db.session.add(ticket)
        db.session.commit()
        
        # Log history
        log_ticket_history(ticket.id, session['user_id'], 'Ticket created')
        
        # Handle file uploads
        if 'attachments' in request.files:
            files = request.files.getlist('attachments')
            for file in files:
                if file and file.filename:
                    filename = secure_filename(file.filename)
                    filepath = os.path.join(app.config['UPLOAD_FOLDER'], 
                                          f"{ticket.ticket_id}_{filename}")
                    file.save(filepath)
                    
                    attachment = Attachment(
                        ticket_id=ticket.id,
                        filename=filename,
                        filepath=filepath,
                        uploaded_by=session['user_id']
                    )
                    db.session.add(attachment)
            db.session.commit()
        
        logger.info(f"Ticket {ticket.ticket_id} created by user {session['username']}")
        flash(f'Ticket {ticket.ticket_id} created successfully!', 'success')
        return redirect(url_for('view_ticket', ticket_id=ticket.ticket_id))
    
    return render_template_string(CREATE_TICKET_TEMPLATE)

@app.route('/ticket/<ticket_id>')
@login_required
def view_ticket(ticket_id):
    """View ticket details"""
    ticket = Ticket.query.filter_by(ticket_id=ticket_id).first_or_404()
    user = User.query.get(session['user_id'])
    
    # Check permissions
    if user.role == 'user' and ticket.user_id != user.id:
        flash('You do not have permission to view this ticket.', 'danger')
        return redirect(url_for('tickets'))
    
    # Get comments (filter internal notes for regular users)
    if user.role in ['admin', 'agent']:
        comments = Comment.query.filter_by(ticket_id=ticket.id).order_by(
            Comment.created_at.asc()
        ).all()
    else:
        comments = Comment.query.filter_by(
            ticket_id=ticket.id,
            is_internal=False
        ).order_by(Comment.created_at.asc()).all()
    
    # Get ticket history
    history = TicketHistory.query.filter_by(ticket_id=ticket.id).order_by(
        TicketHistory.created_at.desc()
    ).all()
    
    # Get attachments
    attachments = Attachment.query.filter_by(ticket_id=ticket.id).all()
    
    # Get agents for assignment (admin/agent only)
    agents = User.query.filter_by(role='agent', is_active=True).all() if user.role in ['admin', 'agent'] else []
    
    return render_template_string(VIEW_TICKET_TEMPLATE,
        user=user,
        ticket=ticket,
        comments=comments,
        history=history,
        attachments=attachments,
        agents=agents
    )

@app.route('/ticket/<ticket_id>/update', methods=['POST'])
@login_required
def update_ticket(ticket_id):
    """Update ticket details"""
    ticket = Ticket.query.filter_by(ticket_id=ticket_id).first_or_404()
    user = User.query.get(session['user_id'])
    
    # Check permissions
    if user.role not in ['admin', 'agent']:
        flash('You do not have permission to update this ticket.', 'danger')
        return redirect(url_for('view_ticket', ticket_id=ticket_id))
    
    action = request.form.get('action')
    
    if action == 'status':
        old_status = ticket.status
        new_status = request.form.get('status')
        ticket.status = new_status
        
        if new_status == 'Resolved' and not ticket.resolved_at:
            ticket.resolved_at = datetime.utcnow()
        elif new_status == 'Closed' and not ticket.closed_at:
            ticket.closed_at = datetime.utcnow()
        
        log_ticket_history(ticket.id, user.id, 'Status changed', old_status, new_status)
        
    elif action == 'priority':
        old_priority = ticket.priority
        new_priority = request.form.get('priority')
        ticket.priority = new_priority
        ticket.sla_deadline = calculate_sla_deadline(new_priority)
        log_ticket_history(ticket.id, user.id, 'Priority changed', old_priority, new_priority)
    
    elif action == 'assign':
        old_agent = ticket.assigned_to
        new_agent = request.form.get('agent_id')
        ticket.assigned_to = int(new_agent) if new_agent else None
        log_ticket_history(ticket.id, user.id, 'Agent assigned', 
                         str(old_agent) if old_agent else 'None',
                         str(new_agent) if new_agent else 'None')
    
    db.session.commit()
    flash('Ticket updated successfully!', 'success')
    return redirect(url_for('view_ticket', ticket_id=ticket_id))

@app.route('/ticket/<ticket_id>/comment', methods=['POST'])
@login_required
def add_comment(ticket_id):
    """Add comment to ticket"""
    ticket = Ticket.query.filter_by(ticket_id=ticket_id).first_or_404()
    user = User.query.get(session['user_id'])
    
    content = request.form.get('content')
    is_internal = request.form.get('is_internal') == 'on'
    
    # Only agents/admins can add internal notes
    if is_internal and user.role not in ['admin', 'agent']:
        is_internal = False
    
    comment = Comment(
        ticket_id=ticket.id,
        user_id=user.id,
        content=content,
        is_internal=is_internal
    )
    
    db.session.add(comment)
    db.session.commit()
    
    log_ticket_history(ticket.id, user.id, 'Comment added')
    
    flash('Comment added successfully!', 'success')
    return redirect(url_for('view_ticket', ticket_id=ticket_id))

@app.route('/knowledge-base')
def knowledge_base():
    """Knowledge base listing"""
    search_query = request.args.get('search', '')
    category_filter = request.args.get('category', '')
    
    query = KnowledgeBase.query.filter_by(is_published=True)
    
    if search_query:
        query = query.filter(
            (KnowledgeBase.title.contains(search_query)) |
            (KnowledgeBase.content.contains(search_query))
        )
    
    if category_filter:
        query = query.filter_by(category=category_filter)
    
    articles = query.order_by(KnowledgeBase.created_at.desc()).all()
    categories = db.session.query(KnowledgeBase.category).distinct().all()
    
    return render_template_string(KNOWLEDGE_BASE_TEMPLATE,
        articles=articles,
        categories=[c[0] for c in categories],
        search_query=search_query,
        category_filter=category_filter
    )

@app.route('/knowledge-base/<int:article_id>')
def view_article(article_id):
    """View knowledge base article"""
    article = KnowledgeBase.query.get_or_404(article_id)
    article.views += 1
    db.session.commit()
    
    return render_template_string(VIEW_ARTICLE_TEMPLATE, article=article)

@app.route('/admin/users')
@role_required('admin')
def manage_users():
    """Manage users (admin only)"""
    users = User.query.all()
    return render_template_string(MANAGE_USERS_TEMPLATE, users=users)

@app.route('/admin/kb/create', methods=['GET', 'POST'])
@role_required('admin', 'agent')
def create_kb_article():
    """Create knowledge base article"""
    if request.method == 'POST':
        title = request.form.get('title')
        content = request.form.get('content')
        category = request.form.get('category')
        
        article = KnowledgeBase(
            title=title,
            content=content,
            category=category,
            created_by=session['user_id']
        )
        
        db.session.add(article)
        db.session.commit()
        
        flash('Knowledge base article created!', 'success')
        return redirect(url_for('knowledge_base'))
    
    return render_template_string(CREATE_KB_TEMPLATE)

@app.route('/export/tickets')
@login_required
@role_required('admin', 'agent')
def export_tickets():
    """Export tickets to CSV"""
    tickets = Ticket.query.all()
    
    output = io.StringIO()
    writer = csv.writer(output)
    
    # Write header
    writer.writerow(['Ticket ID', 'Subject', 'Status', 'Priority', 'Category', 
                    'Created At', 'Assigned To', 'Created By'])
    
    # Write data
    for ticket in tickets:
        assigned_name = User.query.get(ticket.assigned_to).username if ticket.assigned_to else 'Unassigned'
        created_by = User.query.get(ticket.user_id).username
        writer.writerow([
            ticket.ticket_id,
            ticket.subject,
            ticket.status,
            ticket.priority,
            ticket.category,
            ticket.created_at.strftime('%Y-%m-%d %H:%M:%S'),
            assigned_name,
            created_by
        ])
    
    output.seek(0)
    return send_file(
        io.BytesIO(output.getvalue().encode()),
        mimetype='text/csv',
        as_attachment=True,
        download_name=f'tickets_export_{datetime.now().strftime("%Y%m%d")}.csv'
    )

@app.route('/backup')
@role_required('admin')
def backup_database():
    """Backup database"""
    try:
        backup_dir = 'backups'
        os.makedirs(backup_dir, exist_ok=True)
        
        backup_file = os.path.join(backup_dir, 
                                   f'backup_{datetime.now().strftime("%Y%m%d_%H%M%S")}.db')
        shutil.copy2('ticketing_system.db', backup_file)
        
        flash(f'Database backed up successfully to {backup_file}', 'success')
        logger.info(f'Database backup created: {backup_file}')
    except Exception as e:
        flash(f'Backup failed: {str(e)}', 'danger')
        logger.error(f'Backup failed: {str(e)}')
    
    return redirect(url_for('dashboard'))

# ==================== HTML TEMPLATES ====================

BASE_TEMPLATE = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{% block title %}Helpdesk System{% endblock %}</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            display: flex;
            flex-direction: column;
        }
        .navbar {
            background: rgba(255, 255, 255, 0.95);
            backdrop-filter: blur(10px);
            padding: 1rem 2rem;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        .navbar h1 { color: #667eea; font-size: 1.5rem; }
        .nav-links { display: flex; gap: 1.5rem; align-items: center; }
        .nav-links a {
            color: #333;
            text-decoration: none;
            padding: 0.5rem 1rem;
            border-radius: 5px;
            transition: all 0.3s;
        }
        .nav-links a:hover { background: #667eea; color: white; }
        .container {
            max-width: 1200px;
            margin: 2rem auto;
            padding: 0 2rem;
            flex: 1;
        }
        .card {
            background: white;
            border-radius: 10px;
            padding: 2rem;
            box-shadow: 0 4px 15px rgba(0,0,0,0.1);
            margin-bottom: 2rem;
        }
        .btn {
            padding: 0.7rem 1.5rem;
            border: none;
            border-radius: 5px;
            cursor: pointer;
            text-decoration: none;
            display: inline-block;
            transition: all 0.3s;
            font-size: 1rem;
        }
        .btn-primary { background: #667eea; color: white; }
        .btn-primary:hover { background: #5568d3; }
        .btn-success { background: #48bb78; color: white; }
        .btn-success:hover { background: #38a169; }
        .btn-danger { background: #f56565; color: white; }
        .btn-danger:hover { background: #e53e3e; }
        .btn-warning { background: #ed8936; color: white; }
        .btn-warning:hover { background: #dd6b20; }
        .form-group {
            margin-bottom: 1.5rem;
        }
        .form-group label {
            display: block;
            margin-bottom: 0.5rem;
            color: #333;
            font-weight: 500;
        }
        .form-group input, .form-group textarea, .form-group select {
            width: 100%;
            padding: 0.8rem;
            border: 1px solid #ddd;
            border-radius: 5px;
            font-size: 1rem;
        }
        .form-group textarea { min-height: 120px; resize: vertical; }
        .alert {
            padding: 1rem;
            border-radius: 5px;
            margin-bottom: 1rem;
        }
        .alert-success { background: #c6f6d5; color: #22543d; }
        .alert-danger { background: #fed7d7; color: #742a2a; }
        .alert-warning { background: #feebc8; color: #7c2d12; }
        .alert-info { background: #bee3f8; color: #2c5282; }
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 1.5rem;
            margin-bottom: 2rem;
        }
        .stat-card {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 1.5rem;
            border-radius: 10px;
            text-align: center;
        }
        .stat-card h3 { font-size: 2rem; margin-bottom: 0.5rem; }
        .stat-card p { opacity: 0.9; }
        .ticket-list { list-style: none; }
        .ticket-item {
            background: #f7fafc;
            padding: 1rem;
            margin-bottom: 1rem;
            border-radius: 5px;
            border-left: 4px solid #667eea;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        .ticket-item:hover { background: #edf2f7; }
        .priority-critical { border-left-color: #f56565; }
        .priority-high { border-left-color: #ed8936; }
        .priority-medium { border-left-color: #ecc94b; }
        .priority-low { border-left-color: #48bb78; }
        .badge {
            padding: 0.3rem 0.8rem;
            border-radius: 20px;
            font-size: 0.85rem;
            font-weight: 500;
            margin: 0 0.3rem;
        }
        .badge-open { background: #bee3f8; color: #2c5282; }
        .badge-progress { background: #feebc8; color: #7c2d12; }
        .badge-resolved { background: #c6f6d5; color: #22543d; }
        .badge-closed { background: #e2e8f0; color: #2d3748; }
        table { width: 100%; border-collapse: collapse; }
        table th, table td { padding: 1rem; text-align: left; border-bottom: 1px solid #e2e8f0; }
        table th { background: #f7fafc; font-weight: 600; }
        table tr:hover { background: #f7fafc; }
        .comment-section { margin-top: 2rem; }
        .comment {
            background: #f7fafc;
            padding: 1rem;
            border-radius: 5px;
            margin-bottom: 1rem;
            border-left: 3px solid #667eea;
        }
        .comment-internal { border-left-color: #ed8936; background: #fffaf0; }
        .comment-header { display: flex; justify-content: space-between; margin-bottom: 0.5rem; }
        .comment-author { font-weight: 600; color: #667eea; }
        .comment-date { color: #718096; font-size: 0.9rem; }
        .history-item {
            padding: 0.8rem;
            border-left: 2px solid #e2e8f0;
            margin-bottom: 0.5rem;
            font-size: 0.95rem;
        }
        .filter-bar {
            display: flex;
            gap: 1rem;
            margin-bottom: 1.5rem;
            flex-wrap: wrap;
        }
        .filter-bar input, .filter-bar select {
            padding: 0.6rem;
            border: 1px solid #ddd;
            border-radius: 5px;
            flex: 1;
            min-width: 150px;
        }
    </style>
</head>
<body>
    {% if session.user_id %}
    <nav class="navbar">
        <h1>🎫 Helpdesk System</h1>
        <div class="nav-links">
            <a href="{{ url_for('dashboard') }}">Dashboard</a>
            <a href="{{ url_for('tickets') }}">Tickets</a>
            <a href="{{ url_for('create_ticket') }}">New Ticket</a>
            <a href="{{ url_for('knowledge_base') }}">Knowledge Base</a>
            {% if session.role in ['admin', 'agent'] %}
            <a href="{{ url_for('manage_users') }}">Users</a>
            {% endif %}
            <span style="color: #667eea;">{{ session.username }} ({{ session.role }})</span>
            <a href="{{ url_for('logout') }}">Logout</a>
        </div>
    </nav>
    {% endif %}
    
    <div class="container">
        {% with messages = get_flashed_messages(with_categories=true) %}
            {% if messages %}
                {% for category, message in messages %}
                    <div class="alert alert-{{ category }}">{{ message }}</div>
                {% endfor %}
            {% endif %}
        {% endwith %}
        
        {% block content %}{% endblock %}
    </div>
</body>
</html>
'''

LOGIN_TEMPLATE = BASE_TEMPLATE.replace('{% block content %}{% endblock %}', '''
{% block content %}
<div class="card" style="max-width: 500px; margin: 5rem auto;">
    <h2 style="text-align: center; color: #667eea; margin-bottom: 2rem;">Login to Helpdesk</h2>
    <form method="POST">
        <div class="form-group">
            <label>Username</label>
            <input type="text" name="username" required autofocus>
        </div>
        <div class="form-group">
            <label>Password</label>
            <input type="password" name="password" required>
        </div>
        <button type="submit" class="btn btn-primary" style="width: 100%;">Login</button>
    </form>
    <p style="text-align: center; margin-top: 1rem;">
        Don't have an account? <a href="{{ url_for('register') }}" style="color: #667eea;">Register here</a>
    </p>
</div>
{% endblock %}
''')

REGISTER_TEMPLATE = BASE_TEMPLATE.replace('{% block content %}{% endblock %}', '''
{% block content %}
<div class="card" style="max-width: 500px; margin: 5rem auto;">
    <h2 style="text-align: center; color: #667eea; margin-bottom: 2rem;">Register Account</h2>
    <form method="POST">
        <div class="form-group">
            <label>Username</label>
            <input type="text" name="username" required autofocus>
        </div>
        <div class="form-group">
            <label>Email</label>
            <input type="email" name="email" required>
        </div>
        <div class="form-group">
            <label>Password</label>
            <input type="password" name="password" required>
        </div>
        <button type="submit" class="btn btn-primary" style="width: 100%;">Register</button>
    </form>
    <p style="text-align: center; margin-top: 1rem;">
        Already have an account? <a href="{{ url_for('login') }}" style="color: #667eea;">Login here</a>
    </p>
</div>
{% endblock %}
''')

DASHBOARD_TEMPLATE = BASE_TEMPLATE.replace('{% block content %}{% endblock %}', '''
{% block content %}
<h2 style="margin-bottom: 2rem;">Dashboard</h2>

<div class="stats-grid">
    <div class="stat-card">
        <h3>{{ total_tickets }}</h3>
        <p>Total Tickets</p>
    </div>
    <div class="stat-card" style="background: linear-gradient(135deg, #48bb78 0%, #38a169 100%);">
        <h3>{{ open_tickets }}</h3>
        <p>Open Tickets</p>
    </div>
    <div class="stat-card" style="background: linear-gradient(135deg, #ed8936 0%, #dd6b20 100%);">
        <h3>{{ in_progress }}</h3>
        <p>In Progress</p>
    </div>
    <div class="stat-card" style="background: linear-gradient(135deg, #4299e1 0%, #3182ce 100%);">
        <h3>{{ resolved }}</h3>
        <p>Resolved</p>
    </div>
    {% if user.role == 'admin' %}
    <div class="stat-card" style="background: linear-gradient(135deg, #9f7aea 0%, #805ad5 100%);">
        <h3>{{ avg_resolution }}h</h3>
        <p>Avg Resolution Time</p>
    </div>
    {% endif %}
</div>

{% if user.role == 'admin' and agent_stats %}
<div class="card">
    <h3 style="margin-bottom: 1rem;">Agent Performance</h3>
    <table>
        <thead>
            <tr>
                <th>Agent</th>
                <th>Total Tickets</th>
                <th>Resolved</th>
                <th>Resolution Rate</th>
            </tr>
        </thead>
        <tbody>
            {% for agent in agent_stats %}
            <tr>
                <td>{{ agent.name }}</td>
                <td>{{ agent.total }}</td>
                <td>{{ agent.resolved }}</td>
                <td>{{ "%.1f"|format((agent.resolved / agent.total * 100) if agent.total > 0 else 0) }}%</td>
            </tr>
            {% endfor %}
        </tbody>
    </table>
</div>
{% endif %}

<div class="card">
    <h3 style="margin-bottom: 1rem;">Recent Tickets</h3>
    <ul class="ticket-list">
        {% for ticket in recent_tickets %}
        <li class="ticket-item priority-{{ ticket.priority.lower() }}">
            <div>
                <strong><a href="{{ url_for('view_ticket', ticket_id=ticket.ticket_id) }}" style="color: #667eea; text-decoration: none;">{{ ticket.ticket_id }}</a></strong> - {{ ticket.subject }}
                <br>
                <small style="color: #718096;">Created: {{ ticket.created_at.strftime('%Y-%m-%d %H:%M') }}</small>
            </div>
            <div>
                <span class="badge badge-{{ ticket.status.lower().replace(' ', '') }}">{{ ticket.status }}</span>
                <span class="badge" style="background: #e2e8f0; color: #2d3748;">{{ ticket.priority }}</span>
            </div>
        </li>
        {% endfor %}
    </ul>
</div>
{% endblock %}
''')

TICKETS_TEMPLATE = BASE_TEMPLATE.replace('{% block content %}{% endblock %}', '''
{% block content %}
<div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 2rem;">
    <h2>All Tickets</h2>
    <a href="{{ url_for('create_ticket') }}" class="btn btn-primary">Create New Ticket</a>
</div>

<div class="card">
    <form method="GET" class="filter-bar">
        <input type="text" name="search" placeholder="Search tickets..." value="{{ search_query }}">
        <select name="status">
            <option value="">All Status</option>
            <option value="Open" {% if status_filter == 'Open' %}selected{% endif %}>Open</option>
            <option value="In Progress" {% if status_filter == 'In Progress' %}selected{% endif %}>In Progress</option>
            <option value="Resolved" {% if status_filter == 'Resolved' %}selected{% endif %}>Resolved</option>
            <option value="Closed" {% if status_filter == 'Closed' %}selected{% endif %}>Closed</option>
        </select>
        <select name="priority">
            <option value="">All Priority</option>
            <option value="Critical" {% if priority_filter == 'Critical' %}selected{% endif %}>Critical</option>
            <option value="High" {% if priority_filter == 'High' %}selected{% endif %}>High</option>
            <option value="Medium" {% if priority_filter == 'Medium' %}selected{% endif %}>Medium</option>
            <option value="Low" {% if priority_filter == 'Low' %}selected{% endif %}>Low</option>
        </select>
        <button type="submit" class="btn btn-primary">Filter</button>
        <a href="{{ url_for('tickets') }}" class="btn" style="background: #e2e8f0; color: #2d3748;">Clear</a>
    </form>
    
    <table>
        <thead>
            <tr>
                <th>Ticket ID</th>
                <th>Subject</th>
                <th>Priority</th>
                <th>Status</th>
                <th>Category</th>
                <th>Created</th>
                <th>Actions</th>
            </tr>
        </thead>
        <tbody>
            {% for ticket in tickets %}
            <tr>
                <td><strong>{{ ticket.ticket_id }}</strong></td>
                <td>{{ ticket.subject[:50] }}...</td>
                <td><span class="badge" style="background: 
                    {% if ticket.priority == 'Critical' %}#f56565
                    {% elif ticket.priority == 'High' %}#ed8936
                    {% elif ticket.priority == 'Medium' %}#ecc94b
                    {% else %}#48bb78{% endif %}; color: white;">{{ ticket.priority }}</span></td>
                <td><span class="badge badge-{{ ticket.status.lower().replace(' ', '') }}">{{ ticket.status }}</span></td>
                <td>{{ ticket.category }}</td>
                <td>{{ ticket.created_at.strftime('%Y-%m-%d') }}</td>
                <td><a href="{{ url_for('view_ticket', ticket_id=ticket.ticket_id) }}" class="btn btn-primary" style="padding: 0.4rem 0.8rem;">View</a></td>
            </tr>
            {% endfor %}
        </tbody>
    </table>
</div>
{% endblock %}
''')

CREATE_TICKET_TEMPLATE = BASE_TEMPLATE.replace('{% block content %}{% endblock %}', '''
{% block content %}
<h2 style="margin-bottom: 2rem;">Create New Ticket</h2>

<div class="card">
    <form method="POST" enctype="multipart/form-data">
        <div class="form-group">
            <label>Subject *</label>
            <input type="text" name="subject" required>
        </div>
        
        <div class="form-group">
            <label>Description *</label>
            <textarea name="description" required></textarea>
        </div>
        
        <div class="form-group">
            <label>Priority *</label>
            <select name="priority" required>
                <option value="Low">Low</option>
                <option value="Medium" selected>Medium</option>
                <option value="High">High</option>
                <option value="Critical">Critical</option>
            </select>
        </div>
        
        <div class="form-group">
            <label>Category *</label>
            <select name="category" required>
                <option value="Technical">Technical Issue</option>
                <option value="Billing">Billing</option>
                <option value="Account">Account</option>
                <option value="Feature Request">Feature Request</option>
                <option value="Bug Report">Bug Report</option>
                <option value="Other">Other</option>
            </select>
        </div>
        
        <div class="form-group">
            <label>Attachments</label>
            <input type="file" name="attachments" multiple>
            <small style="color: #718096;">Maximum 16MB per file</small>
        </div>
        
        <div style="display: flex; gap: 1rem;">
            <button type="submit" class="btn btn-primary">Create Ticket</button>
            <a href="{{ url_for('tickets') }}" class="btn" style="background: #e2e8f0; color: #2d3748;">Cancel</a>
        </div>
    </form>
</div>
{% endblock %}
''')

VIEW_TICKET_TEMPLATE = BASE_TEMPLATE.replace('{% block content %}{% endblock %}', '''
{% block content %}
<div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 2rem;">
    <h2>Ticket: {{ ticket.ticket_id }}</h2>
    <a href="{{ url_for('tickets') }}" class="btn" style="background: #e2e8f0; color: #2d3748;">Back to Tickets</a>
</div>

<div class="card">
    <div style="display: flex; justify-content: space-between; align-items: start; margin-bottom: 2rem;">
        <div>
            <h3>{{ ticket.subject }}</h3>
            <p style="color: #718096; margin-top: 0.5rem;">
                Created by {{ ticket.creator.username }} on {{ ticket.created_at.strftime('%Y-%m-%d %H:%M') }}
            </p>
        </div>
        <div>
            <span class="badge badge-{{ ticket.status.lower().replace(' ', '') }}">{{ ticket.status }}</span>
            <span class="badge" style="background: 
                {% if ticket.priority == 'Critical' %}#f56565
                {% elif ticket.priority == 'High' %}#ed8936
                {% elif ticket.priority == 'Medium' %}#ecc94b
                {% else %}#48bb78{% endif %}; color: white;">{{ ticket.priority }}</span>
        </div>
    </div>
    
    <div style="background: #f7fafc; padding: 1.5rem; border-radius: 5px; margin-bottom: 2rem;">
        <h4 style="margin-bottom: 1rem;">Description</h4>
        <p style="white-space: pre-wrap;">{{ ticket.description }}</p>
    </div>
    
    <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 1rem; margin-bottom: 2rem;">
        <div>
            <strong>Category:</strong> {{ ticket.category }}
        </div>
        <div>
            <strong>Assigned To:</strong> {{ ticket.agent.username if ticket.agent else 'Unassigned' }}
        </div>
        <div>
            <strong>SLA Deadline:</strong> {{ ticket.sla_deadline.strftime('%Y-%m-%d %H:%M') if ticket.sla_deadline else 'N/A' }}
        </div>
        {% if ticket.resolved_at %}
        <div>
            <strong>Resolved:</strong> {{ ticket.resolved_at.strftime('%Y-%m-%d %H:%M') }}
        </div>
        {% endif %}
    </div>
    
    {% if attachments %}
    <div style="margin-bottom: 2rem;">
        <h4 style="margin-bottom: 1rem;">Attachments</h4>
        <ul style="list-style: none;">
            {% for attachment in attachments %}
            <li style="padding: 0.5rem; background: #f7fafc; margin-bottom: 0.5rem; border-radius: 3px;">
                📎 {{ attachment.filename }} <small style="color: #718096;">(uploaded by {{ attachment.user.username }})</small>
            </li>
            {% endfor %}
        </ul>
    </div>
    {% endif %}
    
    {% if user.role in ['admin', 'agent'] %}
    <div style="border-top: 2px solid #e2e8f0; padding-top: 2rem; margin-bottom: 2rem;">
        <h4 style="margin-bottom: 1rem;">Update Ticket</h4>
        <div style="display: flex; gap: 1rem; flex-wrap: wrap;">
            <form method="POST" action="{{ url_for('update_ticket', ticket_id=ticket.ticket_id) }}" style="display: flex; gap: 0.5rem;">
                <input type="hidden" name="action" value="status">
                <select name="status" style="padding: 0.5rem; border: 1px solid #ddd; border-radius: 5px;">
                    <option value="Open" {% if ticket.status == 'Open' %}selected{% endif %}>Open</option>
                    <option value="In Progress" {% if ticket.status == 'In Progress' %}selected{% endif %}>In Progress</option>
                    <option value="Resolved" {% if ticket.status == 'Resolved' %}selected{% endif %}>Resolved</option>
                    <option value="Closed" {% if ticket.status == 'Closed' %}selected{% endif %}>Closed</option>
                </select>
                <button type="submit" class="btn btn-primary" style="padding: 0.5rem 1rem;">Update Status</button>
            </form>
            
            <form method="POST" action="{{ url_for('update_ticket', ticket_id=ticket.ticket_id) }}" style="display: flex; gap: 0.5rem;">
                <input type="hidden" name="action" value="priority">
                <select name="priority" style="padding: 0.5rem; border: 1px solid #ddd; border-radius: 5px;">
                    <option value="Low" {% if ticket.priority == 'Low' %}selected{% endif %}>Low</option>
                    <option value="Medium" {% if ticket.priority == 'Medium' %}selected{% endif %}>Medium</option>
                    <option value="High" {% if ticket.priority == 'High' %}selected{% endif %}>High</option>
                    <option value="Critical" {% if ticket.priority == 'Critical' %}selected{% endif %}>Critical</option>
                </select>
                <button type="submit" class="btn btn-warning" style="padding: 0.5rem 1rem;">Update Priority</button>
            </form>
            
            <form method="POST" action="{{ url_for('update_ticket', ticket_id=ticket.ticket_id) }}" style="display: flex; gap: 0.5rem;">
                <input type="hidden" name="action" value="assign">
                <select name="agent_id" style="padding: 0.5rem; border: 1px solid #ddd; border-radius: 5px;">
                    <option value="">Unassigned</option>
                    {% for agent in agents %}
                    <option value="{{ agent.id }}" {% if ticket.assigned_to == agent.id %}selected{% endif %}>{{ agent.username }}</option>
                    {% endfor %}
                </select>
                <button type="submit" class="btn btn-success" style="padding: 0.5rem 1rem;">Assign Agent</button>
            </form>
        </div>
    </div>
    {% endif %}
</div>

<div class="card">
    <h3 style="margin-bottom: 1.5rem;">Comments & Discussion</h3>
    
    {% for comment in comments %}
    <div class="comment {% if comment.is_internal %}comment-internal{% endif %}">
        <div class="comment-header">
            <span class="comment-author">{{ comment.user.username }}</span>
            <span class="comment-date">{{ comment.created_at.strftime('%Y-%m-%d %H:%M') }}
                {% if comment.is_internal %}<span class="badge badge-progress">Internal Note</span>{% endif %}
            </span>
        </div>
        <p style="white-space: pre-wrap;">{{ comment.content }}</p>
    </div>
    {% endfor %}
    
    <form method="POST" action="{{ url_for('add_comment', ticket_id=ticket.ticket_id) }}" style="margin-top: 2rem;">
        <div class="form-group">
            <label>Add Comment</label>
            <textarea name="content" required placeholder="Enter your comment..."></textarea>
        </div>
        {% if user.role in ['admin', 'agent'] %}
        <div style="margin-bottom: 1rem;">
            <label style="display: flex; align-items: center; gap: 0.5rem;">
                <input type="checkbox" name="is_internal">
                <span>Internal Note (visible to agents only)</span>
            </label>
        </div>
        {% endif %}
        <button type="submit" class="btn btn-primary">Add Comment</button>
    </form>
</div>

<div class="card">
    <h3 style="margin-bottom: 1.5rem;">Ticket History</h3>
    {% for entry in history %}
    <div class="history-item">
        <strong>{{ entry.user.username }}</strong> {{ entry.action }}
        {% if entry.old_value and entry.new_value %}
        ({{ entry.old_value }} → {{ entry.new_value }})
        {% endif %}
        <br>
        <small style="color: #718096;">{{ entry.created_at.strftime('%Y-%m-%d %H:%M:%S') }}</small>
    </div>
    {% endfor %}
</div>
{% endblock %}
''')

KNOWLEDGE_BASE_TEMPLATE = BASE_TEMPLATE.replace('{% block content %}{% endblock %}', '''
{% block content %}
<div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 2rem;">
    <h2>Knowledge Base</h2>
    {% if session.role in ['admin', 'agent'] %}
    <a href="{{ url_for('create_kb_article') }}" class="btn btn-primary">Create Article</a>
    {% endif %}
</div>

<div class="card">
    <form method="GET" class="filter-bar">
        <input type="text" name="search" placeholder="Search articles..." value="{{ search_query }}">
        <select name="category">
            <option value="">All Categories</option>
            {% for cat in categories %}
            <option value="{{ cat }}" {% if category_filter == cat %}selected{% endif %}>{{ cat }}</option>
            {% endfor %}
        </select>
        <button type="submit" class="btn btn-primary">Search</button>
    </form>
    
    <div style="margin-top: 2rem;">
        {% for article in articles %}
        <div style="background: #f7fafc; padding: 1.5rem; margin-bottom: 1rem; border-radius: 5px;">
            <h3><a href="{{ url_for('view_article', article_id=article.id) }}" style="color: #667eea; text-decoration: none;">{{ article.title }}</a></h3>
            <p style="color: #718096; margin-top: 0.5rem;">
                Category: {{ article.category }} | Views: {{ article.views }} | Updated: {{ article.updated_at.strftime('%Y-%m-%d') }}
            </p>
        </div>
        {% endfor %}
    </div>
</div>
{% endblock %}
''')

CREATE_KB_TEMPLATE = BASE_TEMPLATE.replace('{% block content %}{% endblock %}', '''
{% block content %}
<h2 style="margin-bottom: 2rem;">Create Knowledge Base Article</h2>

<div class="card">
    <form method="POST">
        <div class="form-group">
            <label>Title *</label>
            <input type="text" name="title" required>
        </div>
        
        <div class="form-group">
            <label>Category *</label>
            <select name="category" required>
                <option value="Getting Started">Getting Started</option>
                <option value="Account">Account</option>
                <option value="Technical">Technical</option>
                <option value="Billing">Billing</option>
                <option value="Troubleshooting">Troubleshooting</option>
                <option value="FAQ">FAQ</option>
            </select>
        </div>
        
        <div class="form-group">
            <label>Content *</label>
            <textarea name="content" required style="min-height: 300px;"></textarea>
        </div>
        
        <div style="display: flex; gap: 1rem;">
            <button type="submit" class="btn btn-primary">Create Article</button>
            <a href="{{ url_for('knowledge_base') }}" class="btn" style="background: #e2e8f0; color: #2d3748;">Cancel</a>
        </div>
    </form>
</div>
{% endblock %}
''')

MANAGE_USERS_TEMPLATE = BASE_TEMPLATE.replace('{% block content %}{% endblock %}', '''
{% block content %}
<h2 style="margin-bottom: 2rem;">User Management</h2>

<div class="card">
    <table>
        <thead>
            <tr>
                <th>Username</th>
                <th>Email</th>
                <th>Role</th>
                <th>Status</th>
                <th>Created</th>
                <th>Tickets Created</th>
                <th>Tickets Assigned</th>
            </tr>
        </thead>
        <tbody>
            {% for user in users %}
            <tr>
                <td><strong>{{ user.username }}</strong></td>
                <td>{{ user.email }}</td>
                <td><span class="badge badge-info">{{ user.role }}</span></td>
                <td>
                    {% if user.is_active %}
                    <span class="badge badge-resolved">Active</span>
                    {% else %}
                    <span class="badge badge-closed">Inactive</span>
                    {% endif %}
                </td>
                <td>{{ user.created_at.strftime('%Y-%m-%d') }}</td>
                <td>{{ user.tickets_created|length }}</td>
                <td>{{ user.tickets_assigned|length if user.role == 'agent' else 'N/A' }}</td>
            </tr>
            {% endfor %}
        </tbody>
    </table>
</div>
{% endblock %}
''')

# ==================== INITIALIZATION ====================

def init_database():
    """Initialize database with tables and sample data"""
    with app.app_context():
        db.create_all()
        
        # Check if admin exists
        if not User.query.filter_by(username='admin').first():
            # Create default admin user
            admin = User(
                username='admin',
                email='admin@helpdesk.com',
                password_hash=generate_password_hash('admin123'),
                role='admin'
            )
            
            # Create default agent
            agent = User(
                username='agent1',
                email='agent1@helpdesk.com',
                password_hash=generate_password_hash('agent123'),
                role='agent'
            )
            
            # Create default user
            user = User(
                username='user1',
                email='user1@helpdesk.com',
                password_hash=generate_password_hash('user123'),
                role='user'
            )
            
            db.session.add_all([admin, agent, user])
            db.session.commit()
            
            # Create sample knowledge base articles
            kb1 = KnowledgeBase(
                title='How to Create a Ticket',
                content='''To create a new ticket:

1. Click on "New Ticket" in the navigation bar
2. Fill in the required fields:
   - Subject: Brief description of your issue
   - Description: Detailed explanation of the problem
   - Priority: Select based on urgency
   - Category: Choose the most appropriate category
3. Optionally attach files if needed
4. Click "Create Ticket"

You will receive a ticket ID that you can use to track your request.''',
                category='Getting Started',
                created_by=admin.id
            )
            
            kb2 = KnowledgeBase(
                title='Understanding Priority Levels',
                content='''Priority levels help us address your issues effectively:

- Critical: System down, business-critical issue (4 hour SLA)
- High: Major functionality impaired (24 hour SLA)
- Medium: Non-critical issue affecting some users (72 hour SLA)
- Low: Minor issue or feature request (7 day SLA)

SLA times represent our target response times, not resolution times.''',
                category='FAQ',
                created_by=admin.id
            )
            
            kb3 = KnowledgeBase(
                title='Troubleshooting Login Issues',
                content='''If you're having trouble logging in:

1. Verify your username and password are correct
2. Check if Caps Lock is enabled
3. Try resetting your password using the "Forgot Password" link
4. Clear your browser cache and cookies
5. Try a different browser or incognito mode
6. If the issue persists, create a ticket for assistance

Common causes:
- Incorrect credentials
- Account deactivation
- Browser compatibility issues
- Network connectivity problems''',
                category='Troubleshooting',
                created_by=admin.id
            )
            
            db.session.add_all([kb1, kb2, kb3])
            db.session.commit()
            
            # Create a sample ticket
            sample_ticket = Ticket(
                ticket_id=generate_ticket_id(),
                subject='Sample Ticket - Welcome to the System',
                description='This is a sample ticket to demonstrate the ticketing system. You can view, update, and comment on tickets.',
                priority='Medium',
                category='Technical',
                user_id=user.id,
                assigned_to=agent.id,
                sla_deadline=calculate_sla_deadline('Medium')
            )
            
            db.session.add(sample_ticket)
            db.session.commit()
            
            # Add a comment to the sample ticket
            sample_comment = Comment(
                ticket_id=sample_ticket.id,
                user_id=agent.id,
                content='Thank you for your ticket. We are looking into this issue and will update you shortly.',
                is_internal=False
            )
            
            db.session.add(sample_comment)
            
            # Log history
            log_ticket_history(sample_ticket.id, user.id, 'Ticket created')
            log_ticket_history(sample_ticket.id, agent.id, 'Agent assigned', None, f'Agent: {agent.username}')
            
            db.session.commit()
            
            logger.info('Database initialized with sample data')
            print("\n" + "="*60)
            print("Database initialized successfully!")
            print("="*60)
            print("\nDefault Login Credentials:")
            print("-" * 60)
            print("Admin Account:")
            print("  Username: admin")
            print("  Password: admin123")
            print("\nAgent Account:")
            print("  Username: agent1")
            print("  Password: agent123")
            print("\nUser Account:")
            print("  Username: user1")
            print("  Password: user123")
            print("="*60)
            print("\nAccess the system at: http://localhost:5000")
            print("="*60 + "\n")

# ==================== MAIN EXECUTION ====================

if __name__ == '__main__':
    # Initialize database
    init_database()
    
    # Run the application
    print("\nStarting Helpdesk Ticketing System...")
    print("Press Ctrl+C to stop the server\n")
    
    app.run(debug=True, host='0.0.0.0', port=5000)
