"""
IndustrialShield AI v3.0 — Flask REST API
Production-grade backend for ICS anomaly detection
"""

from flask import Flask, request, jsonify, send_file
from flask_cors import CORS
import sqlite3
import pickle
import logging
import os
import json
import csv
import io
import hashlib
import secrets
from datetime import datetime, timedelta
from functools import wraps
from sklearn.ensemble import IsolationForest
import numpy as np

# ─── APP SETUP ──────────────────────────────────────────────────
app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "*"}})

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(name)s — %(message)s',
    handlers=[
        logging.FileHandler('app.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger('industrialshield')

DB_PATH   = 'database.db'
MODEL_PATH = 'model.pkl'
VERSION   = '3.0.0'

# ─── NORMAL OPERATING RANGES ─────────────────────────────────────
THRESHOLDS = {
    'temperature': {'min': 60, 'max': 85, 'warn': 85, 'crit': 95},
    'pressure':    {'min': 2.5,'max': 5.5, 'warn': 5.5,'crit': 6.0},
    'vibration':   {'min': 0.1,'max': 2.5, 'warn': 2.5,'crit': 3.0},
}

# ─── DATABASE ────────────────────────────────────────────────────
def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.executescript('''
        CREATE TABLE IF NOT EXISTS users (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            username   TEXT UNIQUE NOT NULL,
            password   TEXT NOT NULL,
            role       TEXT DEFAULT 'Operator',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_login TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS predictions (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            temperature   REAL NOT NULL,
            pressure      REAL NOT NULL,
            vibration     REAL NOT NULL,
            anomaly_score REAL,
            is_anomaly    INTEGER,
            level         TEXT,
            confidence    REAL,
            reasons       TEXT,
            recommendations TEXT,
            user_id       INTEGER,
            timestamp     TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS alerts (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            level      TEXT NOT NULL,
            message    TEXT,
            sensor     TEXT,
            value      REAL,
            threshold  REAL,
            resolved   INTEGER DEFAULT 0,
            timestamp  TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS model_logs (
            id        INTEGER PRIMARY KEY AUTOINCREMENT,
            event     TEXT,
            details   TEXT,
            user_id   INTEGER,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS sessions (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id    INTEGER NOT NULL,
            token      TEXT UNIQUE NOT NULL,
            expires_at TIMESTAMP NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
    ''')

    # Seed users (passwords hashed for prod)
    c.execute("INSERT OR IGNORE INTO users (username, password, role) VALUES (?, ?, ?)",
              ('admin', _hash('admin123'), 'Admin'))
    c.execute("INSERT OR IGNORE INTO users (username, password, role) VALUES (?, ?, ?)",
              ('operator', _hash('op123'), 'Operator'))
    conn.commit()
    conn.close()
    logger.info("[OK] Database initialized")

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def _hash(password):
    """Simple SHA-256 hash — use bcrypt in production"""
    return hashlib.sha256(password.encode()).hexdigest()

# ─── ML MODEL ────────────────────────────────────────────────────
def generate_baseline(n=600):
    """Generate synthetic normal operating data for training"""
    np.random.seed(42)
    return np.column_stack([
        np.random.uniform(60, 85, n),   # temperature
        np.random.uniform(2.5, 5.5, n), # pressure
        np.random.uniform(0.1, 2.5, n), # vibration
    ])

def train_model(extra_data=None, contamination=0.05):
    """Train Isolation Forest with baseline + optional new data"""
    X = generate_baseline(600)
    if extra_data and len(extra_data) > 0:
        extra = np.array(extra_data)
        X = np.vstack([X, extra])
        logger.info(f"Retraining with {len(extra_data)} extra samples")

    model = IsolationForest(
        n_estimators=120,
        max_samples=256,
        contamination=contamination,
        random_state=42
    )
    model.fit(X)

    with open(MODEL_PATH, 'wb') as f:
        pickle.dump(model, f)

    logger.info(f"[OK] Model trained on {len(X)} samples")
    return model

def load_model():
    if os.path.exists(MODEL_PATH):
        with open(MODEL_PATH, 'rb') as f:
            return pickle.load(f)
    logger.info("No saved model found — training fresh")
    return train_model()

model = None

# ─── AUTH ────────────────────────────────────────────────────────
def _auth_user(auth_header):
    """Returns user dict or None"""
    if not auth_header or not auth_header.startswith('Bearer '):
        return None
    token = auth_header[7:]

    # Support simple "username:password" tokens (demo mode)
    if ':' in token:
        parts = token.split(':', 1)
        conn = get_db()
        user = conn.execute(
            "SELECT * FROM users WHERE username=? AND password=?",
            (parts[0], _hash(parts[1]))
        ).fetchone()
        # Fallback: unhashed passwords for demo
        if not user:
            user = conn.execute(
                "SELECT * FROM users WHERE username=? AND password=?",
                (parts[0], parts[1])
            ).fetchone()
        conn.close()
        return dict(user) if user else None
    return None

def require_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        user = _auth_user(request.headers.get('Authorization', ''))
        if not user:
            return jsonify({'error': 'Unauthorized', 'code': 401}), 401
        request.current_user = user
        return f(*args, **kwargs)
    return decorated

def require_admin(f):
    @wraps(f)
    @require_auth
    def decorated(*args, **kwargs):
        if request.current_user.get('role') != 'Admin':
            return jsonify({'error': 'Forbidden — Admin role required', 'code': 403}), 403
        return f(*args, **kwargs)
    return decorated

# ─── VALIDATION ──────────────────────────────────────────────────
def validate_readings(data):
    errors = []
    ranges = {'temperature': (-50, 500), 'pressure': (0, 100), 'vibration': (0, 50)}
    for field, (mn, mx) in ranges.items():
        if field not in data:
            errors.append(f'Missing: {field}')
        elif not isinstance(data[field], (int, float)):
            errors.append(f'{field} must be numeric')
        elif not (mn <= data[field] <= mx):
            errors.append(f'{field} out of valid range [{mn}, {mx}]')
    return errors

# ─── EXPLANATION ENGINE ──────────────────────────────────────────
def explain_anomaly(temp, press, vib, score):
    reasons = []
    recommendations = []
    feature_importance = {}

    # Temperature analysis
    temp_dev = max(0, temp - THRESHOLDS['temperature']['max']) / 10
    if temp > THRESHOLDS['temperature']['crit']:
        reasons.append(f"CRITICAL: Temperature {temp:.1f}°C — {temp - 85:.1f}°C above safe limit")
        recommendations.append("Immediately shut down cooling subsystem for inspection")
        recommendations.append("Check refrigerant levels and heat exchanger fouling")
        feature_importance['temperature'] = min(temp_dev * 2, 1.0)
    elif temp > THRESHOLDS['temperature']['warn']:
        reasons.append(f"WARNING: Temperature {temp:.1f}°C exceeds {THRESHOLDS['temperature']['warn']}°C threshold")
        recommendations.append("Increase cooling fan speed and monitor trend closely")
        feature_importance['temperature'] = temp_dev

    # Pressure analysis
    press_dev = max(0, press - THRESHOLDS['pressure']['max']) / 1.0
    if press > THRESHOLDS['pressure']['crit']:
        reasons.append(f"CRITICAL: Pressure {press:.2f} bar — exceeds max rated pressure {THRESHOLDS['pressure']['crit']} bar")
        recommendations.append("Engage emergency pressure relief — check safety valves")
        recommendations.append("Reduce process load and inspect inlet/outlet pipework")
        feature_importance['pressure'] = min(press_dev, 1.0)
    elif press > THRESHOLDS['pressure']['warn']:
        reasons.append(f"WARNING: Pressure {press:.2f} bar above normal range")
        recommendations.append("Monitor for blockages and inspect filters")
        feature_importance['pressure'] = press_dev * 0.5

    # Vibration analysis
    vib_dev = max(0, vib - THRESHOLDS['vibration']['max']) / 1.0
    if vib > THRESHOLDS['vibration']['crit']:
        reasons.append(f"CRITICAL: Vibration {vib:.2f} mm/s — severe mechanical risk")
        recommendations.append("STOP MACHINE — inspect bearings, shaft alignment immediately")
        recommendations.append("Check for loose mechanical connections and foundation bolts")
        feature_importance['vibration'] = min(vib_dev, 1.0)
    elif vib > THRESHOLDS['vibration']['warn']:
        reasons.append(f"WARNING: Vibration {vib:.2f} mm/s above threshold")
        recommendations.append("Schedule predictive maintenance — bearing inspection within 24h")
        feature_importance['vibration'] = vib_dev * 0.5

    if not reasons and score > 0.5:
        reasons.append("Statistical anomaly detected by Isolation Forest (multi-variate pattern deviation)")
        recommendations.append("Review operational logs for recent changes in process parameters")
        recommendations.append("Compare with historical baseline patterns over the past 24 hours")

    if not recommendations:
        recommendations.append("Continue monitoring — no immediate action required")

    return reasons, recommendations, feature_importance

# ─── ROUTES ──────────────────────────────────────────────────────

@app.route('/health', methods=['GET'])
def health():
    return jsonify({
        'status': 'healthy',
        'version': VERSION,
        'model_loaded': model is not None,
        'model_file': os.path.exists(MODEL_PATH),
        'db_file': os.path.exists(DB_PATH),
        'timestamp': datetime.now().isoformat(),
        'thresholds': THRESHOLDS
    })

@app.route('/auth/login', methods=['POST'])
def login():
    data = request.json or {}
    username = data.get('username', '').strip()
    password = data.get('password', '')

    if not username or not password:
        return jsonify({'error': 'Username and password required'}), 400

    conn = get_db()
    # Try hashed first, then plain (demo compatibility)
    user = conn.execute(
        "SELECT id, username, role FROM users WHERE username=? AND (password=? OR password=?)",
        (username, _hash(password), password)
    ).fetchone()

    if user:
        conn.execute("UPDATE users SET last_login=? WHERE id=?",
                     (datetime.now().isoformat(), user['id']))
        conn.commit()
    conn.close()

    if not user:
        logger.warning(f"Failed login: {username}")
        return jsonify({'error': 'Invalid credentials'}), 401

    token = f"{username}:{password}"
    logger.info(f"Login: {username} ({user['role']})")
    return jsonify({'success': True, 'token': token, 'user': dict(user)})

@app.route('/auth/register', methods=['POST'])
def register():
    data = request.json or {}
    username = data.get('username', '').strip()
    password = data.get('password', '')
    role = data.get('role', 'Operator')

    if not username or not password:
        return jsonify({'error': 'Username and password required'}), 400
    if len(username) < 3:
        return jsonify({'error': 'Username must be at least 3 characters'}), 400
    if len(password) < 4:
        return jsonify({'error': 'Password must be at least 4 characters'}), 400
    if role not in ('Admin', 'Operator'):
        return jsonify({'error': 'Role must be Admin or Operator'}), 400

    try:
        conn = get_db()
        conn.execute(
            "INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
            (username, _hash(password), role)
        )
        conn.commit()
        conn.close()
        logger.info(f"New user registered: {username} ({role})")
        return jsonify({'success': True, 'message': 'Account created successfully'})
    except sqlite3.IntegrityError:
        return jsonify({'error': 'Username already taken'}), 409

@app.route('/predict', methods=['POST'])
@require_auth
def predict():
    """
    POST /predict
    Body: {"temperature": 78.5, "pressure": 4.2, "vibration": 1.1}
    Returns anomaly detection result with explanation and confidence
    """
    global model
    data = request.json or {}

    errors = validate_readings(data)
    if errors:
        return jsonify({'error': 'Validation failed', 'details': errors}), 400

    temp  = float(data['temperature'])
    press = float(data['pressure'])
    vib   = float(data['vibration'])

    if model is None:
        model = load_model()

    X = np.array([[temp, press, vib]])
    raw_score   = -model.score_samples(X)[0]
    normalized  = float(np.clip(raw_score / 2.0, 0, 1))
    is_anomaly  = bool(model.predict(X)[0] == -1)

    level = 'safe'
    if is_anomaly:
        level = 'critical' if normalized > 0.72 else 'warning'

    reasons, recommendations, feature_importance = explain_anomaly(temp, press, vib, normalized)

    result = {
        'temperature':       temp,
        'pressure':          press,
        'vibration':         vib,
        'anomaly_score':     round(normalized, 4),
        'is_anomaly':        is_anomaly,
        'level':             level,
        'confidence':        round(normalized * 100, 1),
        'reasons':           reasons,
        'recommendations':   recommendations,
        'feature_importance': feature_importance,
        'thresholds':        THRESHOLDS,
        'timestamp':         datetime.now().isoformat()
    }

    # Persist to DB
    conn = get_db()
    conn.execute(
        """INSERT INTO predictions
           (temperature, pressure, vibration, anomaly_score, is_anomaly,
            level, confidence, reasons, recommendations, user_id)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (temp, press, vib, normalized, int(is_anomaly),
         level, result['confidence'],
         json.dumps(reasons), json.dumps(recommendations),
         request.current_user['id'])
    )

    # Log alerts for non-safe events
    if level != 'safe':
        conn.execute(
            "INSERT INTO alerts (level, message, sensor, value, threshold) VALUES (?, ?, ?, ?, ?)",
            (level, '; '.join(reasons[:1]), 'multi', normalized, 0.5)
        )

    conn.commit()
    conn.close()

    logger.info(f"Predict: T={temp}°C P={press}bar V={vib}mm/s → {level.upper()} ({normalized:.3f})")
    return jsonify(result)

@app.route('/predict/batch', methods=['POST'])
@require_auth
def predict_batch():
    """POST /predict/batch — Analyze multiple readings at once"""
    global model
    data = request.json or {}
    readings = data.get('readings', [])

    if not readings or not isinstance(readings, list):
        return jsonify({'error': 'readings array required'}), 400
    if len(readings) > 100:
        return jsonify({'error': 'Maximum 100 readings per batch'}), 400

    if model is None:
        model = load_model()

    results = []
    for r in readings:
        errors = validate_readings(r)
        if errors:
            results.append({'error': errors, 'input': r})
            continue
        temp, press, vib = float(r['temperature']), float(r['pressure']), float(r['vibration'])
        X = np.array([[temp, press, vib]])
        normalized = float(np.clip(-model.score_samples(X)[0] / 2.0, 0, 1))
        is_anomaly = bool(model.predict(X)[0] == -1)
        level = 'safe' if not is_anomaly else ('critical' if normalized > 0.72 else 'warning')
        results.append({'temperature': temp, 'pressure': press, 'vibration': vib,
                        'anomaly_score': round(normalized, 4), 'is_anomaly': is_anomaly,
                        'level': level, 'confidence': round(normalized * 100, 1)})

    return jsonify({'results': results, 'count': len(results)})

@app.route('/history', methods=['GET'])
@require_auth
def get_history():
    limit        = min(int(request.args.get('limit', 100)), 1000)
    level_filter = request.args.get('level')
    start_date   = request.args.get('start')
    end_date     = request.args.get('end')
    offset       = int(request.args.get('offset', 0))

    query = "SELECT * FROM predictions WHERE 1=1"
    params = []
    if level_filter:
        query += " AND level=?"; params.append(level_filter)
    if start_date:
        query += " AND timestamp>=?"; params.append(start_date)
    if end_date:
        query += " AND timestamp<=?"; params.append(end_date)
    query += f" ORDER BY timestamp DESC LIMIT {limit} OFFSET {offset}"

    conn = get_db()
    rows = conn.execute(query, params).fetchall()
    total = conn.execute("SELECT COUNT(*) FROM predictions").fetchone()[0]
    conn.close()

    records = []
    for row in rows:
        r = dict(row)
        r['reasons']        = json.loads(r['reasons']) if r['reasons'] else []
        r['recommendations'] = json.loads(r['recommendations']) if r['recommendations'] else []
        records.append(r)

    return jsonify({'records': records, 'total': total, 'returned': len(records), 'offset': offset})

@app.route('/history/export', methods=['GET'])
@require_auth
def export_csv():
    conn = get_db()
    rows = conn.execute("SELECT * FROM predictions ORDER BY timestamp DESC").fetchall()
    conn.close()

    output = io.StringIO()
    w = csv.writer(output)
    w.writerow(['ID','Timestamp','Temperature(C)','Pressure(bar)','Vibration(mm/s)',
                'AnomalyScore','IsAnomaly','Level','Confidence(%)'])
    for row in rows:
        w.writerow([row['id'], row['timestamp'],
                    f"{row['temperature']:.2f}", f"{row['pressure']:.3f}", f"{row['vibration']:.3f}",
                    f"{row['anomaly_score']:.4f}", 'Yes' if row['is_anomaly'] else 'No',
                    row['level'], f"{row['confidence']:.1f}"])
    output.seek(0)

    return send_file(
        io.BytesIO(output.read().encode()),
        mimetype='text/csv',
        as_attachment=True,
        download_name=f'ics_report_{datetime.now().strftime("%Y%m%d_%H%M%S")}.csv'
    )

@app.route('/history/stats', methods=['GET'])
@require_auth
def get_stats():
    conn = get_db()
    s = conn.execute("""
        SELECT
            COUNT(*)                                           AS total,
            SUM(CASE WHEN is_anomaly=1 THEN 1 ELSE 0 END)    AS anomalies,
            SUM(CASE WHEN level='critical' THEN 1 ELSE 0 END) AS criticals,
            SUM(CASE WHEN level='warning'  THEN 1 ELSE 0 END) AS warnings,
            AVG(temperature)                                   AS avg_temp,
            MAX(temperature)                                   AS max_temp,
            MIN(temperature)                                   AS min_temp,
            AVG(pressure)                                      AS avg_press,
            MAX(pressure)                                      AS max_press,
            AVG(vibration)                                     AS avg_vib,
            MAX(vibration)                                     AS max_vib,
            MAX(anomaly_score)                                 AS max_score,
            AVG(anomaly_score)                                 AS avg_score
        FROM predictions
    """).fetchone()
    conn.close()

    total = s['total'] or 0
    return jsonify({
        'total': total,
        'anomalies': s['anomalies'] or 0,
        'criticals': s['criticals'] or 0,
        'warnings':  s['warnings']  or 0,
        'safe':      total - (s['anomalies'] or 0),
        'safe_rate': round((total - (s['anomalies'] or 0)) / max(total, 1) * 100, 1),
        'averages': {
            'temperature': round(s['avg_temp']  or 0, 2),
            'pressure':    round(s['avg_press'] or 0, 3),
            'vibration':   round(s['avg_vib']   or 0, 3),
            'score':       round(s['avg_score'] or 0, 4),
        },
        'peaks': {
            'temperature': round(s['max_temp']  or 0, 2),
            'pressure':    round(s['max_press'] or 0, 3),
            'vibration':   round(s['max_vib']   or 0, 3),
            'score':       round(s['max_score'] or 0, 4),
        }
    })

@app.route('/alerts', methods=['GET'])
@require_auth
def get_alerts():
    limit = min(int(request.args.get('limit', 50)), 200)
    conn  = get_db()
    rows  = conn.execute(
        "SELECT * FROM alerts ORDER BY timestamp DESC LIMIT ?", (limit,)
    ).fetchall()
    conn.close()
    return jsonify({'alerts': [dict(r) for r in rows], 'count': len(rows)})

@app.route('/retrain', methods=['POST'])
@require_admin
def retrain():
    global model
    data = request.json or {}

    extra_samples = []
    if data.get('include_history', False):
        conn = get_db()
        rows = conn.execute(
            "SELECT temperature, pressure, vibration FROM predictions LIMIT 300"
        ).fetchall()
        conn.close()
        extra_samples = [[r['temperature'], r['pressure'], r['vibration']] for r in rows]

    contamination = float(data.get('contamination', 0.05))
    contamination = max(0.01, min(contamination, 0.5))

    model = train_model(extra_samples or None, contamination=contamination)

    conn = get_db()
    conn.execute(
        "INSERT INTO model_logs (event, details, user_id) VALUES (?, ?, ?)",
        ('retrain', json.dumps({
            'extra_samples': len(extra_samples),
            'contamination': contamination,
            'user': request.current_user['username'],
        }), request.current_user['id'])
    )
    conn.commit()
    conn.close()

    logger.info(f"Model retrained by {request.current_user['username']} — {len(extra_samples)} extra samples")
    return jsonify({
        'success': True,
        'message': 'Model retrained successfully',
        'extra_samples': len(extra_samples),
        'contamination': contamination,
        'timestamp': datetime.now().isoformat()
    })

@app.route('/model/info', methods=['GET'])
@require_auth
def model_info():
    global model
    if model is None:
        model = load_model()

    info = {
        'type':           'IsolationForest',
        'algorithm':      'Unsupervised anomaly detection',
        'n_estimators':   model.n_estimators,
        'max_samples':    int(model.max_samples_),
        'contamination':  model.contamination,
        'status':         'ready',
        'thresholds':     THRESHOLDS,
        'version':        VERSION,
    }
    if os.path.exists(MODEL_PATH):
        info['size_kb']       = round(os.path.getsize(MODEL_PATH) / 1024, 1)
        info['last_modified'] = datetime.fromtimestamp(os.path.getmtime(MODEL_PATH)).isoformat()

    return jsonify(info)

@app.route('/users', methods=['GET'])
@require_admin
def list_users():
    conn  = get_db()
    users = conn.execute("SELECT id, username, role, created_at, last_login FROM users").fetchall()
    conn.close()
    return jsonify({'users': [dict(u) for u in users]})

# ─── ERROR HANDLERS ──────────────────────────────────────────────
@app.errorhandler(404)
def not_found(e):
    return jsonify({'error': 'Endpoint not found', 'available': [
        'GET /health', 'POST /auth/login', 'POST /auth/register',
        'POST /predict', 'POST /predict/batch',
        'GET /history', 'GET /history/export', 'GET /history/stats',
        'GET /alerts', 'POST /retrain', 'GET /model/info', 'GET /users'
    ]}), 404

@app.errorhandler(405)
def method_not_allowed(e):
    return jsonify({'error': 'Method not allowed'}), 405

@app.errorhandler(500)
def server_error(e):
    logger.error(f"Server error: {e}")
    return jsonify({'error': 'Internal server error'}), 500

# ─── MAIN ────────────────────────────────────────────────────────
if __name__ == '__main__':
    # Fix UnicodeEncodeError on Windows CMD (cp1252 doesn't support emojis)
    import sys, io
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', errors='replace')

    init_db()
    model = train_model()
    logger.info(f"[OK] IndustrialShield AI v{VERSION} - Backend starting on http://0.0.0.0:5000")
    app.run(debug=True, host='0.0.0.0', port=5000)
