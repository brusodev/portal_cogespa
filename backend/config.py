import os
from datetime import timedelta
from dotenv import load_dotenv

load_dotenv()

BASE_DIR = os.path.abspath(os.path.dirname(__file__))


class Config:
    SECRET_KEY = os.getenv('SECRET_KEY', 'cogespa-secret-key-MUDE-ISSO-2026')
    SQLALCHEMY_DATABASE_URI = f"sqlite:///{os.path.join(BASE_DIR, 'portal.db')}"
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    JWT_SECRET_KEY = os.getenv('JWT_SECRET', 'jwt-cogespa-secret-MUDE-ISSO')
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(hours=8)

    # CORS - domínios permitidos (adicione o seu domínio Vercel)
    CORS_ORIGINS = os.getenv(
        'CORS_ORIGINS',
        'http://localhost:3000,http://localhost:5500,https://portal-cogespa.vercel.app'
    ).split(',')

    # Senha padrão do admin (somente usada no seed inicial)
    DEFAULT_ADMIN_USER = os.getenv('DEFAULT_ADMIN_USER', 'admin')
    DEFAULT_ADMIN_PASSWORD = os.getenv('DEFAULT_ADMIN_PASSWORD', 'cogespa2026')
