const express = require("express");
const session = require("express-session");
const helmet = require("helmet");
const path = require("path");
const bcrypt = require("bcryptjs");
const initializeDatabase = require("./database");

const app = express();
const PORT = process.env.PORT || 3000;

app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({ limit: "100kb" }));
app.use(express.urlencoded({ extended: false }));
app.use(express.static(path.join(__dirname, "public")));

app.use(session({
    name: "ovs.sid",
    secret: process.env.SESSION_SECRET || "replace-this-demo-secret-before-deployment",
    resave: false,
    saveUninitialized: false,
    cookie: {
        httpOnly: true,
        sameSite: "lax",
        secure: process.env.NODE_ENV === "production",
        maxAge: 2 * 60 * 60 * 1000
    }
}));

function rows(db, sql, params = []) {
    const result = db.exec(sql, params);
    if (!result.length) return [];
    return result[0].values.map(values =>
        Object.fromEntries(result[0].columns.map((column, i) => [column, values[i]]))
    );
}
function one(db, sql, params = []) {
    return rows(db, sql, params)[0] || null;
}
function fail(res, status, message) {
    return res.status(status).json({ success: false, message });
}
function requireAdmin(req, res, next) {
    if (!req.session.user || req.session.user.role !== "admin") {
        return fail(res, 401, "Admin login required.");
    }
    next();
}
function requireVoter(req, res, next) {
    if (!req.session.user || req.session.user.role !== "voter") {
        return fail(res, 401, "Please log in as a voter.");
    }
    next();
}

async function startServer() {
    const { db, saveDatabase } = await initializeDatabase();

    app.get("/api/status", (req, res) => {
        res.json({ success: true, message: "Online Voting System API is running." });
    });

    app.get("/api/session", (req, res) => {
        res.json({ success: true, user: req.session.user || null });
    });

    app.post("/api/admin/login", async (req, res) => {
        
app.post("/api/voters/register", async (req, res) => {
    try {
        const fullName = String(req.body.fullName || "").trim();
        const username = String(req.body.username || "")
            .trim()
            .toLowerCase();
        const password = String(req.body.password || "");

        const schoolIdNumber = String(
            req.body.schoolIdNumber || ""
        ).trim().toUpperCase();

        const program = String(req.body.program || "").trim();

        if (fullName.length < 2) {
            return fail(res, 400, "Enter your full name.");
        }

        if (!/^[a-z0-9._-]{3,30}$/.test(username)) {
            return fail(
                res,
                400,
                "Username must be 3–30 characters."
            );
        }

        if (password.length < 8) {
            return fail(
                res,
                400,
                "Password must be at least 8 characters."
            );
        }

        if (!schoolIdNumber || schoolIdNumber.length > 30) {
            return fail(
                res,
                400,
                "Enter a valid School ID Number."
            );
        }

        const allowedPrograms = [
            "CICS - BSIT",
            "CICS - BLIS",
            "CAS - BS Psychology"
        ];

        if (!program) {
            return fail(res, 400, "Select your program.");
        }

        if (!allowedPrograms.includes(program)) {
            return fail(
                res,
                400,
                "Please select a valid program."
            );
        }

        if (
            one(db, "SELECT id FROM voters WHERE username = ?", [
                username
            ])
        ) {
            return fail(
                res,
                409,
                "That username is already registered."
            );
        }

        if (
            one(
                db,
                "SELECT id FROM voters WHERE school_id_number = ?",
                [schoolIdNumber]
            )
        ) {
            return fail(
                res,
                409,
                "That School ID Number is already registered."
            );
        }

        const hash = await bcrypt.hash(password, 10);

        db.run(
            `INSERT INTO voters
            (full_name, username, password_hash,
             school_id_number, program)
             VALUES (?, ?, ?, ?, ?)`,
            [
                fullName,
                username,
                hash,
                schoolIdNumber,
                program
            ]
        );

        saveDatabase();

        res.status(201).json({
            success: true,
            message: "Voter account created. You can now log in."
        });
    } catch (error) {
        console.error("Voter registration:", error);
        fail(res, 500, "Could not register voter.");
    }
});

    });

    app.post("/api/voters/register", async (req, res) => {
        try {
            const fullName = String(req.body.fullName || "").trim();
            const username = String(req.body.username || "").trim().toLowerCase();
            const password = String(req.body.password || "");
            if (fullName.length < 2) return fail(res, 400, "Enter your full name.");
            if (!/^[a-z0-9._-]{3,30}$/.test(username)) {
                return fail(res, 400, "Username must be 3–30 characters (letters, numbers, dot, underscore, hyphen).");
            }
            if (password.length < 8) return fail(res, 400, "Password must be at least 8 characters.");
            if (one(db, "SELECT id FROM voters WHERE username = ?", [username])) {
                return fail(res, 409, "That username is already registered.");
            }
            const hash = await bcrypt.hash(password, 10);
            db.run("INSERT INTO voters (full_name, username, password_hash) VALUES (?, ?, ?)", [fullName, username, hash]);
            saveDatabase();
            res.status(201).json({ success: true, message: "Voter account created. You can now log in." });
        } catch (error) {
            console.error("Voter registration:", error);
            fail(res, 500, "Could not register voter.");
        }
    });

    
    // ADMIN LOGIN
    app.post("/api/admin/login", async (req, res) => {
        try {
            const username = String(req.body.username || "").trim();
            const password = String(req.body.password || "");

            const admin = one(
                db,
                "SELECT id, username, password_hash FROM admins WHERE username = ?",
                [username]
            );

            if (
                !admin ||
                !(await bcrypt.compare(password, admin.password_hash))
            ) {
                return fail(
                    res,
                    401,
                    "Invalid admin username or password."
                );
            }

            req.session.regenerate(error => {
                if (error) {
                    return fail(res, 500, "Could not create session.");
                }

                req.session.user = {
                    id: admin.id,
                    username: admin.username,
                    role: "admin"
                };

                req.session.save(err => {
                    if (err) {
                        return fail(res, 500, "Could not save session.");
                    }

                    res.json({
                        success: true,
                        user: req.session.user
                    });
                });
            });
        } catch (error) {
            console.error("Admin login:", error);
            fail(res, 500, "Server error during admin login.");
        }
    });

    // VOTER REGISTRATION
    app.post("/api/voters/register", async (req, res) => {
        try {
            const fullName = String(req.body.fullName || "").trim();
            const username = String(req.body.username || "")
                .trim()
                .toLowerCase();
            const password = String(req.body.password || "");
            const schoolIdNumber = String(
                req.body.schoolIdNumber || ""
            ).trim().toUpperCase();
            const program = String(req.body.program || "").trim();

            if (fullName.length < 2) {
                return fail(res, 400, "Enter your full name.");
            }

            if (!/^[a-z0-9._-]{3,30}$/.test(username)) {
                return fail(res, 400, "Username must be 3–30 characters.");
            }

            if (password.length < 8) {
                return fail(
                    res,
                    400,
                    "Password must be at least 8 characters."
                );
            }

            if (!schoolIdNumber || schoolIdNumber.length > 30) {
                return fail(res, 400, "Enter a valid School ID Number.");
            }

            const allowedPrograms = [
                "CICS - BSIT",
                "CICS - BLIS",
                "CAS - BS Psychology"
            ];

            if (!allowedPrograms.includes(program)) {
                return fail(res, 400, "Select a valid program.");
            }

            if (
                one(db, "SELECT id FROM voters WHERE username = ?", [
                    username
                ])
            ) {
                return fail(res, 409, "Username is already registered.");
            }

            if (
                one(
                    db,
                    "SELECT id FROM voters WHERE school_id_number = ?",
                    [schoolIdNumber]
                )
            ) {
                return fail(
                    res,
                    409,
                    "School ID Number is already registered."
                );
            }

            const hash = await bcrypt.hash(password, 10);

            db.run(
                `INSERT INTO voters
                (full_name, username, password_hash,
                 school_id_number, program)
                 VALUES (?, ?, ?, ?, ?)`,
                [fullName, username, hash, schoolIdNumber, program]
            );

            saveDatabase();

            res.status(201).json({
                success: true,
                message: "Voter account created. You can now log in."
            });
        } catch (error) {
            console.error("Voter registration:", error);
            fail(res, 500, "Could not register voter.");
        }

        startServer().catch(error => {
    console.error("Failed to start server:", error);
    process.exit(1);
});
    });
}
