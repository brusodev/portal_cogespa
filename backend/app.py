import json
from functools import wraps

from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_jwt_extended import (
    JWTManager, create_access_token, jwt_required, get_jwt_identity
)

from config import Config
from models import db, User, PortalData, AuditLog

# ================================================================
# APP FACTORY
# ================================================================

app = Flask(__name__)
app.config.from_object(Config)

# CORS
CORS(app, origins=Config.CORS_ORIGINS, supports_credentials=True)

# Extensions
db.init_app(app)
jwt = JWTManager(app)


# ================================================================
# HELPERS
# ================================================================

def get_client_ip():
    """Retorna o IP real do cliente (suporte a proxy reverso)."""
    return request.headers.get('X-Forwarded-For', request.remote_addr)


def log_action(action, username, detail=None, data_version=None):
    """Registra uma ação no audit log."""
    entry = AuditLog(
        action=action,
        username=username,
        detail=detail,
        ip_address=get_client_ip(),
        data_version=data_version,
    )
    db.session.add(entry)
    db.session.commit()


def get_current_data():
    """Retorna o registro de dados atual."""
    return PortalData.query.filter_by(is_current=True).first()


def get_next_version():
    """Retorna a próxima versão sequencial."""
    last = PortalData.query.order_by(PortalData.version.desc()).first()
    return (last.version + 1) if last else 1


def admin_required(fn):
    """Decorator que exige role='admin' além do JWT válido."""
    @wraps(fn)
    @jwt_required()
    def wrapper(*args, **kwargs):
        username = get_jwt_identity()
        user = User.query.filter_by(username=username, ativo=True).first()
        if not user or user.role != 'admin':
            return jsonify({"error": "Acesso negado. Apenas administradores."}), 403
        return fn(*args, **kwargs)
    return wrapper


# Dados iniciais padrão
DEFAULT_DATA = {
    "topicos": [
        {
            "id": "limpeza",
            "nome": "Centralização dos Serviços de Limpeza das Unidades Regionais",
            "icone": "fa-building-o",
            "categorias": [
                {
                    "nome": "Avaliação da Execução dos Serviços",
                    "perguntas": [
                        {
                            "pergunta": "Qual é a finalidade da Avaliação de Execução dos Serviços?",
                            "resposta": "A Avaliação de Execução dos Serviços tem como objetivo verificar o desempenho, a regularidade e a qualidade dos serviços prestados mensalmente pela Contratada."
                        },
                        {
                            "pergunta": "Como será realizado a Avaliação de Execução dos Serviços?",
                            "resposta": "A avaliação será realizada por meio de formulário eletrônico, acessado através do link encaminhado aos fiscais no início da execução dos serviços na respectiva U.R.E."
                        },
                        {
                            "pergunta": "Qual é o prazo para envio do Formulário de Avaliação de Execução dos Serviços pelos fiscais Técnicos?",
                            "resposta": "O Formulário de Avaliação deverá ser encaminhado pelos fiscais até o 2º dia útil do mês subsequente ao da prestação dos serviços. O link para preenchimento será fixo e utilizado mensalmente."
                        }
                    ]
                },
                {
                    "nome": "Folha de Ponto",
                    "perguntas": [
                        {
                            "pergunta": "Os dados do cabeçalho da Folha de Ponto devem corresponder à U.R.E ou à Contratada?",
                            "resposta": "Os dados do cabeçalho (Endereço, CNPJ, entre outros) deverão corresponder exclusivamente às informações da Contratada, conforme previsto no contrato."
                        },
                        {
                            "pergunta": "A U.R.E deve manter controle de ponto de funcionários fixos e volantes?",
                            "resposta": "O controle de ponto deverá ser mantido apenas para os funcionários fixos alocados na unidade."
                        },
                        {
                            "pergunta": "Mesmo que a Contratada mantenha controle próprio de ponto, a U.R.E deve manter um controle adicional?",
                            "resposta": "Sim. Independentemente do controle realizado pela Contratada, a U.R.E deverá manter controle próprio de frequência, para fins de Fiscalização interna e acompanhamento da execução contratual."
                        }
                    ]
                },
                {
                    "nome": "Questões Trabalhistas",
                    "perguntas": [
                        {
                            "pergunta": "Quem deve ser comunicado em caso de irregularidades no cumprimento das obrigações trabalhistas?",
                            "resposta": "O Fiscal Técnico deverá informar o Fiscal Administrativo na Sede, para que sejam adotadas as providências cabíveis."
                        },
                        {
                            "pergunta": "Quais profissionais estão autorizados a realizar a limpeza dos sanitários?",
                            "resposta": "A limpeza dos sanitários deverá ser realizada exclusivamente pelo agente de higienização, profissional que recebe o adicional de insalubridade correspondente à atividade. Caso outro empregado execute essa tarefa, será obrigatório o pagamento do respectivo adicional."
                        },
                        {
                            "pergunta": "Como será realizado o controle e a Fiscalização das atividades de limpeza dos sanitários?",
                            "resposta": "A Fiscalização ocorrerá por meio de folha de controle de higienização, disponibilizada nos sanitários, a qual deverá ser preenchida e assinada pelo funcionário responsável após a execução do serviço."
                        }
                    ]
                },
                {
                    "nome": "Funcionários",
                    "perguntas": [
                        {
                            "pergunta": "Quais providências devem ser adotadas em caso de ausência de funcionário?",
                            "resposta": "O Fiscal Técnico deverá acionar a Contratada para providenciar a substituição e, simultaneamente, comunicar o Fiscal Administrativo na Sede, a fim de reforçar a solicitação e registrar a ocorrência."
                        },
                        {
                            "pergunta": "A quantidade de funcionários alocados para a execução dos serviços é fixa?",
                            "resposta": "A Contratada deverá disponibilizar o quantitativo de empregados necessário à adequada execução dos serviços. Dessa forma, caso a quantidade de profissionais alocados na U.R.E não se mostre suficiente para a plena execução contratual, a unidade poderá encaminhar solicitação devidamente fundamentada ao Fiscal Administrativo na Sede, que avaliarão a demanda e a formalizarão junto à Contratada."
                        }
                    ]
                },
                {
                    "nome": "Materiais e Equipamentos",
                    "perguntas": [
                        {
                            "pergunta": "Quais providências devem ser adotadas em caso de falta ou necessidade de substituição de materiais e equipamentos?",
                            "resposta": "O Fiscal Técnico deverá acionar a Contratada para regularização imediata e, concomitantemente, comunicar o Fiscal Administrativo na Sede, a fim de reforçar a solicitação e registrar a ocorrência."
                        },
                        {
                            "pergunta": "Qual é o prazo para reposição ou substituição de materiais faltantes ou considerados inadequados?",
                            "resposta": "A Contratada deverá completar ou substituir os materiais considerados inadequados no prazo máximo de 24 (vinte e quatro) horas, conforme o Termo de Referência."
                        },
                        {
                            "pergunta": "Quando os materiais de limpeza devem ser disponibilizados pela Contratada?",
                            "resposta": "A Contratada deverá fornecer, no início de cada mês, todo o material de limpeza necessário à execução dos serviços no período, em quantidade e qualidade compatíveis com a demanda, mantendo estoque suficiente e realizando reposições sempre que necessário."
                        },
                        {
                            "pergunta": "Qual é o prazo para substituição de equipamentos e utensílios danificados?",
                            "resposta": "Os equipamentos danificados deverão ser substituídos no prazo máximo de 24 (vinte e quatro) horas."
                        }
                    ]
                },
                {
                    "nome": "Início dos Serviços",
                    "perguntas": [
                        {
                            "pergunta": "Como proceder em caso de necessidade de alteração da data de início da execução dos serviços na U.R.E?",
                            "resposta": "O Fiscal Técnico deverá comunicar formalmente o Fiscal Administrativo na Sede, que adotará as providências necessárias junto à Contratada para o ajuste da execução contratual."
                        }
                    ]
                }
            ]
        }
    ]
}


# ================================================================
# ROTAS PÚBLICAS
# ================================================================

@app.route('/api/health', methods=['GET'])
def health():
    """Health check."""
    return jsonify({"status": "ok", "service": "Portal COGESPA API"})


@app.route('/api/dados', methods=['GET'])
def get_dados():
    """Retorna os dados atuais do portal (público, sem autenticação)."""
    current = get_current_data()

    if not current:
        return jsonify(DEFAULT_DATA)

    try:
        data = json.loads(current.data)
    except json.JSONDecodeError:
        return jsonify(DEFAULT_DATA)

    return jsonify(data)


# ================================================================
# AUTENTICAÇÃO
# ================================================================

@app.route('/api/login', methods=['POST'])
def login():
    """Autenticação do admin. Retorna JWT token."""
    body = request.get_json(silent=True)

    if not body or not body.get('username') or not body.get('password'):
        return jsonify({"error": "Usuário e senha são obrigatórios."}), 400

    user = User.query.filter_by(username=body['username'], ativo=True).first()

    if not user or not user.check_password(body['password']):
        log_action('login_failed', body.get('username', '?'), 'Tentativa de login com senha incorreta')
        return jsonify({"error": "Usuário ou senha incorretos."}), 401

    token = create_access_token(identity=user.username)
    log_action('login', user.username, 'Login realizado com sucesso')

    return jsonify({
        "token": token,
        "user": user.to_dict()
    })


# ================================================================
# ROTAS PROTEGIDAS (ADMIN)
# ================================================================

@app.route('/api/dados', methods=['POST'])
@jwt_required()
def save_dados():
    """Salva novos dados do portal. Cria nova versão e registra auditoria."""
    username = get_jwt_identity()
    body = request.get_json(silent=True)

    if not body or not isinstance(body.get('topicos'), list):
        return jsonify({"error": "Formato inválido. Esperado: { topicos: [...] }"}), 400

    # Marcar versão anterior como não atual
    PortalData.query.filter_by(is_current=True).update({'is_current': False})

    # Criar nova versão
    new_version = get_next_version()
    entry = PortalData(
        version=new_version,
        data=json.dumps(body, ensure_ascii=False),
        created_by=username,
        is_current=True,
    )
    db.session.add(entry)
    db.session.commit()

    # Registrar auditoria
    total_topicos = len(body['topicos'])
    total_perguntas = sum(
        len(p)
        for t in body['topicos']
        for c in t.get('categorias', [])
        for p in [c.get('perguntas', [])]
    )

    log_action(
        'save',
        username,
        f'Salvou versão {new_version} com {total_topicos} tópicos e {total_perguntas} perguntas',
        data_version=new_version,
    )

    return jsonify({
        "success": True,
        "message": f"Dados publicados com sucesso! (v{new_version})",
        "version": new_version,
        "total_topicos": total_topicos,
        "total_perguntas": total_perguntas,
    })


@app.route('/api/versions', methods=['GET'])
@jwt_required()
def list_versions():
    """Lista todas as versões salvas (auditoria)."""
    versions = PortalData.query.order_by(PortalData.version.desc()).all()
    return jsonify([v.to_dict() for v in versions])


@app.route('/api/versions/<int:version_id>', methods=['GET'])
@jwt_required()
def get_version(version_id):
    """Retorna os dados de uma versão específica."""
    entry = PortalData.query.filter_by(version=version_id).first()

    if not entry:
        return jsonify({"error": "Versão não encontrada."}), 404

    try:
        data = json.loads(entry.data)
    except json.JSONDecodeError:
        return jsonify({"error": "Erro ao ler dados desta versão."}), 500

    return jsonify({
        "version": entry.to_dict(),
        "data": data,
    })


@app.route('/api/versions/<int:version_id>/restore', methods=['POST'])
@jwt_required()
def restore_version(version_id):
    """Restaura uma versão anterior como versão atual."""
    username = get_jwt_identity()
    entry = PortalData.query.filter_by(version=version_id).first()

    if not entry:
        return jsonify({"error": "Versão não encontrada."}), 404

    # Marcar todas como não atuais
    PortalData.query.filter_by(is_current=True).update({'is_current': False})

    # Criar nova versão com os dados antigos
    new_version = get_next_version()
    restored = PortalData(
        version=new_version,
        data=entry.data,
        created_by=username,
        is_current=True,
    )
    db.session.add(restored)
    db.session.commit()

    log_action(
        'restore',
        username,
        f'Restaurou versão {version_id} como nova versão {new_version}',
        data_version=new_version,
    )

    return jsonify({
        "success": True,
        "message": f"Versão {version_id} restaurada como v{new_version}.",
        "new_version": new_version,
    })


@app.route('/api/audit', methods=['GET'])
@admin_required
def get_audit():
    """Retorna o log de auditoria."""
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 50, type=int)

    query = AuditLog.query.order_by(AuditLog.created_at.desc())
    pagination = query.paginate(page=page, per_page=per_page, error_out=False)

    return jsonify({
        "logs": [log.to_dict() for log in pagination.items],
        "total": pagination.total,
        "page": pagination.page,
        "pages": pagination.pages,
    })


# ================================================================
# GESTÃO DE USUÁRIOS
# ================================================================

@app.route('/api/me', methods=['GET'])
@jwt_required()
def get_me():
    """Retorna os dados do usuário autenticado."""
    username = get_jwt_identity()
    user = User.query.filter_by(username=username, ativo=True).first()
    if not user:
        return jsonify({"error": "Usuário não encontrado."}), 404
    return jsonify(user.to_dict())


@app.route('/api/users', methods=['GET'])
@admin_required
def list_users():
    """Lista todos os usuários. Somente admins."""
    users = User.query.all()
    return jsonify([u.to_dict() for u in users])


@app.route('/api/users', methods=['POST'])
@admin_required
def create_user():
    """Cria um novo usuário. Somente admins."""
    body = request.get_json(silent=True)

    if not body or not body.get('username') or not body.get('password'):
        return jsonify({"error": "Username e password são obrigatórios."}), 400

    if User.query.filter_by(username=body['username']).first():
        return jsonify({"error": "Usuário já existe."}), 409

    role = body.get('role', 'editor')
    if role not in ('admin', 'editor'):
        return jsonify({"error": "Role inválido. Use 'admin' ou 'editor'."}), 400

    user = User(
        username=body['username'],
        nome=body.get('nome', ''),
        role=role,
        ativo=True,
    )
    user.set_password(body['password'])
    db.session.add(user)
    db.session.commit()

    log_action('create_user', get_jwt_identity(), f'Criou usuário: {user.username} (role: {role})')

    return jsonify({"success": True, "user": user.to_dict()}), 201


@app.route('/api/users/<int:user_id>', methods=['PUT'])
@admin_required
def update_user(user_id):
    """Atualiza um usuário (nome, senha, status, role). Somente admins."""
    body = request.get_json(silent=True)
    user = User.query.get(user_id)

    if not user:
        return jsonify({"error": "Usuário não encontrado."}), 404

    if body.get('nome') is not None:
        user.nome = body['nome']
    if body.get('password'):
        user.set_password(body['password'])
    if 'ativo' in body:
        user.ativo = body['ativo']
    if 'role' in body:
        if body['role'] not in ('admin', 'editor'):
            return jsonify({"error": "Role inválido. Use 'admin' ou 'editor'."}), 400
        user.role = body['role']

    db.session.commit()

    log_action('update_user', get_jwt_identity(), f'Atualizou usuário: {user.username}')

    return jsonify({"success": True, "user": user.to_dict()})


# ================================================================
# SEED (popular dados iniciais)
# ================================================================

@app.route('/api/seed', methods=['POST'])
def seed():
    """Popula o banco com dados iniciais. Só funciona se não houver dados."""
    if User.query.first():
        return jsonify({"error": "Banco já foi inicializado. Seed não permitido."}), 400

    # Criar usuário admin padrão
    admin = User(
        username=Config.DEFAULT_ADMIN_USER,
        nome='Administrador',
        role='admin',
        ativo=True,
    )
    admin.set_password(Config.DEFAULT_ADMIN_PASSWORD)
    db.session.add(admin)

    # Criar dados iniciais
    entry = PortalData(
        version=1,
        data=json.dumps(DEFAULT_DATA, ensure_ascii=False),
        created_by='system',
        is_current=True,
    )
    db.session.add(entry)

    # Log
    audit = AuditLog(
        action='seed',
        username='system',
        detail='Dados iniciais populados',
        ip_address=get_client_ip(),
        data_version=1,
    )
    db.session.add(audit)
    db.session.commit()

    return jsonify({
        "success": True,
        "message": "Banco inicializado com sucesso!",
        "admin_user": Config.DEFAULT_ADMIN_USER,
        "admin_password": Config.DEFAULT_ADMIN_PASSWORD,
    })


# ================================================================
# INICIALIZAÇÃO
# ================================================================

with app.app_context():
    db.create_all()

    # Migração: adiciona coluna 'role' se não existir (bancos criados antes desta versão)
    try:
        with db.engine.connect() as conn:
            cols = [row[1] for row in conn.execute(db.text("PRAGMA table_info(users)")).fetchall()]
            if 'role' not in cols:
                conn.execute(db.text("ALTER TABLE users ADD COLUMN role VARCHAR(20) NOT NULL DEFAULT 'editor'"))
                # Garante que o usuário 'admin' padrão fica com role=admin
                conn.execute(db.text("UPDATE users SET role = 'admin' WHERE username = :u"), {"u": Config.DEFAULT_ADMIN_USER})
                conn.commit()
    except Exception as e:
        app.logger.warning(f'Migração role: {e}')


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5001)
