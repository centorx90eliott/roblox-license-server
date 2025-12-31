import express from "express";
import crypto from "crypto";
import pkg from "pg";

const { Pool } = pkg;

const app = express();
app.use(express.json());

// Clé secrète partagée avec Roblox
const SECRET_KEY = "une_longue_cle_secrete_2025";

// Connexion Render PostgreSQL
const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: { rejectUnauthorized: false }
});

// Vérification HMAC
function verifyHMAC(license, userid, timestamp, signature) {
    const message = license + userid + timestamp;
    const hmac = crypto.createHmac("sha256", SECRET_KEY)
                       .update(message)
                       .digest("hex");
    return hmac === signature;
}

app.post("/verify", async (req, res) => {
    const { license, userid, timestamp, signature } = req.body;

    if (!verifyHMAC(license, userid, timestamp, signature)) {
        return res.json({ status: "invalid", reason: "bad_signature" });
    }

    const now = Date.now();

    const result = await pool.query(
        "SELECT * FROM licenses WHERE license = $1",
        [license]
    );

    if (result.rows.length === 0) {
        return res.json({ status: "invalid", reason: "unknown_license" });
    }

    const data = result.rows[0];

    if (data.banned_until && now < data.banned_until) {
        return res.json({ status: "invalid", reason: "license_suspended" });
    }

    const allowed = JSON.parse(data.allowed_ids);

    if (!allowed.includes(userid)) {
        await pool.query(
            "UPDATE licenses SET attempts = attempts + 1 WHERE license = $1",
            [license]
        );

        if (data.attempts + 1 >= 3) {
            const banTime = now + 48 * 60 * 60 * 1000;
            await pool.query(
                "UPDATE licenses SET banned_until = $1 WHERE license = $2",
                [banTime, license]
            );
        }

        return res.json({ status: "invalid", reason: "userid_not_allowed" });
    }

    await pool.query(
        "UPDATE licenses SET last_used = $1, attempts = 0 WHERE license = $2",
        [now, license]
    );

    return res.json({ status: "valid" });
});

app.listen(3000, () => console.log("Server running on port 3000"));
