# core/services.py---config management service
from .models import db, SystemConfig

class ConfigManager:
    @staticmethod
    def get(name, default=None):
        config = SystemConfig.query.filter_by(config_name=name).first()
        return config.config_value if config else default
        
    @staticmethod
    def set(name, value):
        config = SystemConfig.query.filter_by(config_name=name).first()
        if config:
            config.config_value = value
        else:
            config = SystemConfig(config_name=name, config_value=value)
            db.session.add(config)
        db.session.commit()
        return config

    @staticmethod
    def get_security_settings():
        return {
            'login_attempts': ConfigManager.get('login_attempts', 5),
            'password_expiry': ConfigManager.get('password_expiry', 90),
            'session_timeout': ConfigManager.get('session_timeout', False),
            'session_timeout_minutes': ConfigManager.get('session_timeout_minutes', 30)
        }
# core/services.py---API token management service    
class TokenService:
    @staticmethod
    def create_token(description, permissions, expiry_days=90):
        new_token = APIToken(
            description=description,
            permissions=permissions,
            expires_at=datetime.utcnow() + timedelta(days=expiry_days)
        )
        new_token.generate_token()
        db.session.add(new_token)
        db.session.commit()
        return new_token
    
    @staticmethod
    def revoke_token(token_id):
        token = APIToken.query.get(token_id)
        if token:
            token.is_active = False
            db.session.commit()
            return True
        return False
    
    @staticmethod
    def renew_token(token_id):
        token = APIToken.query.get(token_id)
        if token:
            token.generate_token()
            token.expires_at = datetime.utcnow() + timedelta(days=90)
            token.is_active = True
            db.session.commit()
            return token
        return None
    
    @staticmethod
    def delete_token(token_id):
        token = APIToken.query.get(token_id)
        if token:
            db.session.delete(token)
            db.session.commit()
            return True
        return False