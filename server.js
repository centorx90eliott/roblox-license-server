// ====================================
// SERVEUR DE VÉRIFICATION DE LICENCES
// ====================================
// Installation requise: npm install express body-parser crypto better-sqlite3

const express = require('express');
const bodyParser = require('body-parser');
const crypto = require('crypto');
const Database = require('better-sqlite3');

const app = express();
const PORT = process.env.PORT || 3000;

// ⚙️ CONFIGURATION
const SECRET_KEY = "K8xP2mQ9zR4vN7wT5ydTDde7eEssAUF6dgOgvDjUCeAu53Gte86YdWd64U3sA6fG1hJ0dL";
const MAX_ATTEMPTS = 3; // Nombre max de UserIDs différents avant ban
const BAN_DURATION_MS = 48 * 60 * 60 * 1000; // 48 heures

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

// 📊 Base de données SQLite
const db = new Database('licenses.db');

// Création de la table si elle n'existe pas
db.exec(`
  CREATE TABLE IF NOT EXISTS licenses (
    license TEXT PRIMARY KEY,
    owner_id INTEGER NOT NULL,
    allowed_ids TEXT NOT NULL,
    last_used INTEGER,
    unauthorized_attempts TEXT DEFAULT '[]',
    banned_until INTEGER DEFAULT NULL,
    created_at INTEGER DEFAULT (strftime('%s', 'now'))
  )
`);

// Création de la table des logs
db.exec(`
  CREATE TABLE IF NOT EXISTS access_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    license TEXT NOT NULL,
    user_id INTEGER NOT NULL,
    success INTEGER NOT NULL,
    reason TEXT,
    timestamp INTEGER DEFAULT (strftime('%s', 'now'))
  )
`);

// 🔐 Fonction de vérification HMAC
function verifyHMAC(license, userid, timestamp, signature) {
  const message = `${license}${userid}${timestamp}`;
  const expectedSignature = crypto
    .createHmac('sha256', SECRET_KEY)
    .update(message)
    .digest('hex');
  
  return crypto.timingSafeEqual(
    Buffer.from(signature),
    Buffer.from(expectedSignature)
  );
}

// 📝 Logger les accès
function logAccess(license, userId, success, reason = null) {
  const stmt = db.prepare(`
    INSERT INTO access_logs (license, user_id, success, reason)
    VALUES (?, ?, ?, ?)
  `);
  stmt.run(license, userId, success ? 1 : 0, reason);
}

// 🚨 Endpoint principal de vérification
app.post('/verify', (req, res) => {
  const { license, userid, timestamp, signature } = req.body;

  // Validation des paramètres
  if (!license || !userid || !timestamp || !signature) {
    return res.status(400).json({
      valid: false,
      reason: 'Missing required parameters'
    });
  }

  // Vérification du timestamp (max 5 minutes de décalage)
  const now = Math.floor(Date.now() / 1000);
  const requestTime = parseInt(timestamp);
  if (Math.abs(now - requestTime) > 300) {
    logAccess(license, userid, false, 'Timestamp expired');
    return res.status(401).json({
      valid: false,
      reason: 'Request expired'
    });
  }

  // Vérification de la signature HMAC
  if (!verifyHMAC(license, userid, timestamp, signature)) {
    logAccess(license, userid, false, 'Invalid signature');
    return res.status(401).json({
      valid: false,
      reason: 'Invalid signature'
    });
  }

  // Récupération de la licence
  const licenseData = db.prepare('SELECT * FROM licenses WHERE license = ?').get(license);

  if (!licenseData) {
    logAccess(license, userid, false, 'License not found');
    return res.status(404).json({
      valid: false,
      reason: 'License not found'
    });
  }

  // Vérification du ban
  if (licenseData.banned_until && licenseData.banned_until > now) {
    const hoursLeft = Math.ceil((licenseData.banned_until - now) / 3600);
    logAccess(license, userid, false, `Banned (${hoursLeft}h left)`);
    return res.status(403).json({
      valid: false,
      reason: `License suspended for ${hoursLeft} more hours`,
      banned_until: licenseData.banned_until
    });
  }

  // Débannir si le temps est écoulé
  if (licenseData.banned_until && licenseData.banned_until <= now) {
    db.prepare('UPDATE licenses SET banned_until = NULL, unauthorized_attempts = ? WHERE license = ?')
      .run('[]', license);
  }

  // Parse des IDs autorisés et tentatives
  const allowedIds = JSON.parse(licenseData.allowed_ids);
  const unauthorizedAttempts = JSON.parse(licenseData.unauthorized_attempts || '[]');

  // Vérification si l'utilisateur est autorisé
  if (allowedIds.includes(parseInt(userid))) {
    // ✅ ACCÈS AUTORISÉ
    db.prepare('UPDATE licenses SET last_used = ? WHERE license = ?')
      .run(now, license);
    
    logAccess(license, userid, true, 'Authorized access');
    
    return res.json({
      valid: true,
      owner_id: licenseData.owner_id,
      message: 'License valid'
    });
  } else {
    // ❌ ACCÈS NON AUTORISÉ
    
    // Ajouter cette tentative si pas déjà enregistrée
    if (!unauthorizedAttempts.includes(parseInt(userid))) {
      unauthorizedAttempts.push(parseInt(userid));
      
      // Si dépassement du seuil → BAN
      if (unauthorizedAttempts.length >= MAX_ATTEMPTS) {
        const banUntil = now + Math.floor(BAN_DURATION_MS / 1000);
        
        db.prepare(`
          UPDATE licenses 
          SET unauthorized_attempts = ?, banned_until = ?
          WHERE license = ?
        `).run(JSON.stringify(unauthorizedAttempts), banUntil, license);
        
        logAccess(license, userid, false, 'BANNED - Too many unauthorized attempts');
        
        return res.status(403).json({
          valid: false,
          reason: 'License suspended due to unauthorized access attempts',
          banned_until: banUntil
        });
      } else {
        // Mise à jour des tentatives
        db.prepare('UPDATE licenses SET unauthorized_attempts = ? WHERE license = ?')
          .run(JSON.stringify(unauthorizedAttempts), license);
      }
    }
    
    logAccess(license, userid, false, `Unauthorized UserID (${unauthorizedAttempts.length}/${MAX_ATTEMPTS})`);
    
    return res.status(403).json({
      valid: false,
      reason: 'UserID not authorized for this license',
      attempts: unauthorizedAttempts.length,
      max_attempts: MAX_ATTEMPTS
    });
  }
});

// 🔧 ENDPOINT ADMIN : Ajouter une licence
app.post('/admin/add-license', (req, res) => {
  const { admin_key, license, owner_id, allowed_ids } = req.body;

  // Protection admin basique (à améliorer avec un vrai système d'auth)
  if (admin_key !== 'VOTRE_CLE_ADMIN_SECRETE_ICI') {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  try {
    const stmt = db.prepare(`
      INSERT INTO licenses (license, owner_id, allowed_ids)
      VALUES (?, ?, ?)
    `);
    
    stmt.run(license, owner_id, JSON.stringify(allowed_ids));
    
    res.json({
      success: true,
      message: 'License added successfully',
      license: license
    });
  } catch (err) {
    res.status(500).json({
      error: 'Failed to add license',
      details: err.message
    });
  }
});

// 🔧 ENDPOINT ADMIN : Bannir/débannir une licence
app.post('/admin/ban-license', (req, res) => {
  const { admin_key, license, duration_hours } = req.body;

  if (admin_key !== 're43dtr7sfevDiuFgSDFfs13dsOd6534dsf') {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  const now = Math.floor(Date.now() / 1000);
  const banUntil = duration_hours ? now + (duration_hours * 3600) : null;

  db.prepare('UPDATE licenses SET banned_until = ? WHERE license = ?')
    .run(banUntil, license);

  res.json({
    success: true,
    message: banUntil ? `License banned for ${duration_hours}h` : 'License unbanned'
  });
});

// 📊 ENDPOINT ADMIN : Voir les logs d'une licence
app.get('/admin/logs/:license', (req, res) => {
  const { admin_key } = req.query;
  const { license } = req.params;

  if (admin_key !== 'VOTRE_CLE_ADMIN_SECRETE_ICI') {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  const logs = db.prepare(`
    SELECT * FROM access_logs 
    WHERE license = ? 
    ORDER BY timestamp DESC 
    LIMIT 100
  `).all(license);

  res.json({ license, logs });
});

// ❤️ Health check
app.get('/health', (req, res) => {
  res.json({ status: 'online', timestamp: Date.now() });
});

// 🚀 Démarrage du serveur
app.listen(PORT, () => {
  console.log(`✅ License server running on port ${PORT}`);
  console.log(`📝 Database: licenses.db`);
  console.log(`🔐 Secret key configured`);
});

// Gestion de la fermeture propre
process.on('SIGINT', () => {
  db.close();
  process.exit(0);
});
