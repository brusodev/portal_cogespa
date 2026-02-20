from datetime import datetime
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

db = SQLAlchemy()


class User(db.Model):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    nome = db.Column(db.String(120), nullable=True)
    role = db.Column(db.String(20), nullable=False, default='editor')  # 'admin' ou 'editor'
    ativo = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def to_dict(self):
        return {
            'id': self.id,
            'username': self.username,
            'nome': self.nome,
            'role': self.role,
            'ativo': self.ativo,
            'created_at': self.created_at.isoformat() if self.created_at else None,
        }


class PortalData(db.Model):
    """Armazena o JSON completo do portal. Cada save cria uma nova versão."""
    __tablename__ = 'portal_data'

    id = db.Column(db.Integer, primary_key=True)
    version = db.Column(db.Integer, nullable=False, default=1)
    data = db.Column(db.Text, nullable=False)  # JSON string
    created_by = db.Column(db.String(80), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_current = db.Column(db.Boolean, default=True)

    def to_dict(self):
        return {
            'id': self.id,
            'version': self.version,
            'created_by': self.created_by,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'is_current': self.is_current,
        }


class AuditLog(db.Model):
    """Registro de todas as ações realizadas no painel admin."""
    __tablename__ = 'audit_log'

    id = db.Column(db.Integer, primary_key=True)
    action = db.Column(db.String(50), nullable=False)       # login, save, restore, export
    username = db.Column(db.String(80), nullable=False)
    detail = db.Column(db.Text, nullable=True)               # Descrição da ação
    ip_address = db.Column(db.String(45), nullable=True)
    data_version = db.Column(db.Integer, nullable=True)       # Versão dos dados alterada
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {
            'id': self.id,
            'action': self.action,
            'username': self.username,
            'detail': self.detail,
            'ip_address': self.ip_address,
            'data_version': self.data_version,
            'created_at': self.created_at.isoformat() if self.created_at else None,
        }
