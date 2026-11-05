
const express = require("express");
const session = require("express-session");
const helmet = require("helmet");
const bcrypt = require("bcryptjs");
const path = require("path");
const initializeDatabase = require("./database");

const app = express();
const PORT = process.env.PORT || 3000;

const PROGRAMS = [
  "CICS - BSIT",
  "CICS - BLIS",
  "CAS - BS Psychology",
  "CAS - BSSW",
  "CAS - AB Economics",
  "CAS - AB Sociology",
  "CBM - BSBA",
  "CBM - BSTM",
  "CTE - BEEd",
  "CTE - BSEd",
  "CCJE - BS Criminology"
];

app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.use(session({
  name: "sjcb-voting.sid",
  secret: process.env.SESSION_SECRET || "change-this-sjcb-session-secret",
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    sameSite: "lax",
    secure: process.env.NODE_ENV === "production",
    maxAge: 2 * 60 * 60 * 1000
  }
}));

app.use(express.static(path.join(__dirname, "public")));

let db;
let saveDatabase;

function all(sql, params = []) {
  const statement = db.prepare(sql);
  const result = [];

  try {
    statement.bind(params);

    while (statement.step()) {
      result.push(statement.getAsObject());
    }
  } finally {
    statement.free();
  }

  return result;
}

function one(sql, params = []) {
  return all(sql, params)[0] || null;
}

function run(sql, params = []) {
  db.run(sql, params);
  saveDatabase();
}

function fail(res, status, message) {
  return res.status(status).json({ error: message });
}

function logActivity(actor, action) {
  try {
    db.run(
      "INSERT INTO activity_logs (actor, action) VALUES (?, ?)",
      [String(actor || "System"), String(action || "Activity")]
    );
    saveDatabase();
  } catch (error) {
    console.error("Activity log error:", error.message);
  }
}

// --------------------------------------------------
// AUTHENTICATION MIDDLEWARE
// --------------------------------------------------

function requireLogin(req, res, next) {
  if (!req.session.account) {
    return fail(res, 401, "Please log in first.");
  }
  next();
}

function requireVoter(req, res, next) {
  if (!req.session.account || req.session.account.role !== "voter") {
    return fail(res, 403, "Voter access required.");
  }
  next();
}

function requireAdmin(req, res, next) {
  if (!req.session.account || req.session.account.role !== "admin") {
    return fail(res, 403, "Administrator access required.");
  }
  next();
}

// --------------------------------------------------
// POSITION AND VOTING HELPERS
// --------------------------------------------------

function getPositions() {
  return all(`
    SELECT id, title, sort_order
    FROM positions
    ORDER BY sort_order, id
  `);
}

function getProgress(voterId) {
  const positions = getPositions();

  const votedIds = all(
    "SELECT position_id FROM votes WHERE voter_id = ?",
    [voterId]
  ).map(row => Number(row.position_id));

  const nextPosition = positions.find(
    position => !votedIds.includes(Number(position.id))
  ) || null;

  return {
    positions,
    votedPositionIds: votedIds,
    nextPosition,
    completed: nextPosition === null,
    completedPositions: votedIds.length,
    totalPositions: positions.length
  };
}

// --------------------------------------------------
// PUBLIC API
// --------------------------------------------------

app.get("/api/health", (req, res) => {
  res.json({ ok: true });
});

app.get("/api/session", (req, res) => {
  res.json({
    account: req.session.account || null,
    loggedIn: Boolean(req.session.account)
  });
});

app.get("/api/programs", (req, res) => {
  res.json(PROGRAMS);
});

app.get("/api/positions", (req, res) => {
  res.json(getPositions());
});

app.get("/api/candidates", (req, res) => {
  res.json(all(`
    SELECT
      c.id,
      c.full_name,
      c.position_id,
      c.platform,
      p.title AS position_title
    FROM candidates c
    JOIN positions p ON p.id = c.position_id
    ORDER BY p.sort_order, c.full_name
  `));
});

// --------------------------------------------------
// VOTER REGISTRATION
// --------------------------------------------------

app.post("/api/voters/register", async (req, res) => {
  try {
    const fullName = String(req.body.fullName || "").trim();
    const schoolId = String(req.body.schoolIdNumber || "").trim();
    const program = String(req.body.program || "").trim();
    const password = String(req.body.password || "");
    const confirmPassword = String(req.body.confirmPassword || "");

    if (!fullName || !schoolId || !program || !password || !confirmPassword) {
      return fail(res, 400, "Please complete all fields.");
    }

    if (!PROGRAMS.includes(program)) {
      return fail(res, 400, "Please select a valid program.");
    }

    if (password.length < 8) {
      return fail(res, 400, "Password must be at least 8 characters.");
    }

    if (password !== confirmPassword) {
      return fail(res, 400, "Passwords do not match.");
    }

    const existing = one(
      `SELECT id FROM voters
       WHERE school_id_number = ? OR username = ?`,
      [schoolId, schoolId]
    );

    if (existing) {
      return fail(res, 409, "School ID Number is already registered.");
    }

    const passwordHash = await bcrypt.hash(password, 10);

    run(
      `INSERT INTO voters
       (full_name, username, school_id_number, program, password_hash)
       VALUES (?, ?, ?, ?, ?)`,
      [fullName, schoolId, schoolId, program, passwordHash]
    );

    logActivity(schoolId, "Voter registered");

    res.status(201).json({
      message: "Registration successful. You can now log in."
    });
  } catch (error) {
    console.error("Registration error:", error);
    fail(res, 500, "Registration failed.");
  }
});

// --------------------------------------------------
// VOTER LOGIN
// --------------------------------------------------

app.post("/api/voters/login", async (req, res) => {
  try {
    const schoolId = String(req.body.schoolIdNumber || "").trim();
    const password = String(req.body.password || "");

    const voter = one(
      `SELECT id, full_name, username, school_id_number,
              program, password_hash
       FROM voters
       WHERE school_id_number = ? OR username = ?`,
      [schoolId, schoolId]
    );

    if (!voter || !(await bcrypt.compare(password, voter.password_hash))) {
      return fail(res, 401, "Incorrect School ID Number or password.");
    }

    req.session.regenerate(error => {
      if (error) return fail(res, 500, "Could not create login session.");

      req.session.account = {
        id: voter.id,
        name: voter.full_name,
        username: voter.username || voter.school_id_number,
        schoolIdNumber: voter.school_id_number,
        program: voter.program,
        role: "voter"
      };

      req.session.save(saveError => {
        if (saveError) return fail(res, 500, "Could not save login session.");

        logActivity(voter.school_id_number, "Voter logged in");

        res.json({
          message: "Login successful.",
          account: req.session.account
        });
      });
    });
  } catch (error) {
    console.error("Voter login error:", error);
    fail(res, 500, "Voter login failed.");
  }
});

// --------------------------------------------------
// ADMIN LOGIN
// --------------------------------------------------

app.post("/api/admin/login", async (req, res) => {
  try {
    const username = String(req.body.username || "").trim();
    const password = String(req.body.password || "");

    const admin = one(
      "SELECT id, username, password_hash FROM admins WHERE username = ?",
      [username]
    );

    if (!admin || !(await bcrypt.compare(password, admin.password_hash))) {
      return fail(res, 401, "Incorrect administrator username or password.");
    }

    req.session.regenerate(error => {
      if (error) return fail(res, 500, "Could not create login session.");

      req.session.account = {
        id: admin.id,
        name: admin.username,
        username: admin.username,
        role: "admin"
      };

      req.session.save(saveError => {
        if (saveError) return fail(res, 500, "Could not save login session.");

        logActivity(username, "Administrator logged in");

        res.json({
          message: "Administrator login successful.",
          account: req.session.account
        });
      });
    });
  } catch (error) {
    console.error("Admin login error:", error);
    fail(res, 500, "Administrator login failed.");
  }
});

// --------------------------------------------------
// LOGOUT
// --------------------------------------------------

app.post("/api/logout", (req, res) => {
  const account = req.session.account;

  if (account) {
    logActivity(
      account.schoolIdNumber || account.username || account.name,
      "Logged out"
    );
  }

  req.session.destroy(error => {
    if (error) return fail(res, 500, "Logout failed.");

    res.clearCookie("sjcb-voting.sid");
    res.json({ message: "Logged out successfully." });
  });
});

// --------------------------------------------------
// CHANGE PASSWORD
// --------------------------------------------------

app.post("/api/settings/password", requireLogin, async (req, res) => {
  try {
    const {
      currentPassword,
      newPassword,
      confirmPassword
    } = req.body;

    if (!newPassword || newPassword.length < 8) {
      return fail(res, 400, "New password must have at least 8 characters.");
    }

    if (newPassword !== confirmPassword) {
      return fail(res, 400, "New passwords do not match.");
    }

    const account = req.session.account;
    const table = account.role === "admin" ? "admins" : "voters";

    const record = one(
      `SELECT id, password_hash FROM ${table} WHERE id = ?`,
      [account.id]
    );

    if (!record || !(await bcrypt.compare(currentPassword, record.password_hash))) {
      return fail(res, 400, "Current password is incorrect.");
    }

    const passwordHash = await bcrypt.hash(newPassword, 10);

    run(
      `UPDATE ${table} SET password_hash = ? WHERE id = ?`,
      [passwordHash, account.id]
    );

    logActivity(account.username || account.name, "Changed password");

    res.json({ message: "Password updated successfully." });
  } catch (error) {
    console.error("Password update error:", error);
    fail(res, 500, "Could not update password.");
  }
});

// --------------------------------------------------
// ADMIN: POSITIONS
// --------------------------------------------------

app.post("/api/admin/positions", requireAdmin, (req, res) => {
  const title = String(req.body.title || "").trim();

  if (!title) {
    return fail(res, 400, "Position title is required.");
  }

  if (one(
    "SELECT id FROM positions WHERE lower(title) = lower(?)",
    [title]
  )) {
    return fail(res, 409, "Position already exists.");
  }

  const maxOrder = Number(
    one("SELECT COALESCE(MAX(sort_order), 0) AS total FROM positions").total
  );

  run(
    "INSERT INTO positions (title, sort_order) VALUES (?, ?)",
    [title, maxOrder + 1]
  );

  logActivity(req.session.account.username, `Added position: ${title}`);

  res.status(201).json({ message: "Position added successfully." });
});

// --------------------------------------------------
// ADMIN: CANDIDATES
// --------------------------------------------------

app.post("/api/admin/candidates", requireAdmin, (req, res) => {
  const fullName = String(req.body.fullName || "").trim();
  const positionId = Number(req.body.positionId);
  const platform = String(req.body.platform || "").trim();

  if (!fullName || !Number.isInteger(positionId)) {
    return fail(res, 400, "Candidate name and position are required.");
  }

  if (!one("SELECT id FROM positions WHERE id = ?", [positionId])) {
    return fail(res, 400, "Selected position does not exist.");
  }

  run(
    `INSERT INTO candidates (full_name, position_id, platform)
     VALUES (?, ?, ?)`,
    [fullName, positionId, platform]
  );

  logActivity(req.session.account.username, `Added candidate: ${fullName}`);

  res.status(201).json({ message: "Candidate registered successfully." });
});

app.delete("/api/admin/candidates/:id", requireAdmin, (req, res) => {
  const id = Number(req.params.id);

  if (!Number.isInteger(id)) {
    return fail(res, 400, "Invalid candidate ID.");
  }

  const candidate = one(
    "SELECT id, full_name FROM candidates WHERE id = ?",
    [id]
  );

  if (!candidate) {
    return fail(res, 404, "Candidate not found.");
  }

  if (one("SELECT id FROM votes WHERE candidate_id = ? LIMIT 1", [id])) {
    return fail(res, 409, "Cannot delete a candidate who has received votes.");
  }

  run("DELETE FROM candidates WHERE id = ?", [id]);

  logActivity(
    req.session.account.username,
    `Deleted candidate: ${candidate.full_name}`
  );

  res.json({ message: "Candidate deleted successfully." });
});

// --------------------------------------------------
// VOTER: VOTING PROGRESS AND VOTE HISTORY
// --------------------------------------------------

app.get("/api/voter/progress", requireVoter, (req, res) => {
  res.json(getProgress(req.session.account.id));
});

app.get("/api/voter/my-votes", requireVoter, (req, res) => {
  res.json(all(`
    SELECT
      v.id,
      v.position_id,
      p.title AS position_title,
      c.full_name AS candidate_name,
      v.created_at
    FROM votes v
    JOIN positions p ON p.id = v.position_id
    JOIN candidates c ON c.id = v.candidate_id
    WHERE v.voter_id = ?
    ORDER BY p.sort_order, p.id
  `, [req.session.account.id]));
});

// --------------------------------------------------
// VOTER: SUBMIT VOTE
// --------------------------------------------------

app.post("/api/votes", requireVoter, (req, res) => {
  try {
    const voterId = req.session.account.id;
    const candidateId = Number(req.body.candidateId);

    const progress = getProgress(voterId);

    if (!progress.nextPosition) {
      return fail(res, 409, "You have already voted for every position.");
    }

    if (!Number.isInteger(candidateId)) {
      return fail(res, 400, "Please select a candidate.");
    }

    const candidate = one(
      "SELECT id, full_name, position_id FROM candidates WHERE id = ?",
      [candidateId]
    );

    if (!candidate) {
      return fail(res, 404, "Candidate not found.");
    }

    if (Number(candidate.position_id) !== Number(progress.nextPosition.id)) {
      return fail(
        res,
        400,
        `You must vote for ${progress.nextPosition.title} first.`
      );
    }

    run(
      `INSERT INTO votes (voter_id, candidate_id, position_id)
       VALUES (?, ?, ?)`,
      [voterId, candidateId, progress.nextPosition.id]
    );

    logActivity(
      req.session.account.schoolIdNumber,
      `Voted for ${candidate.full_name} (${progress.nextPosition.title})`
    );

    const updated = getProgress(voterId);

    res.json({
      message: updated.completed
        ? "Vote accepted. You have completed all positions."
        : "Vote accepted. You may proceed to the next position.",
      progress: updated
    });
  } catch (error) {
    console.error("Voting error:", error);

    if (String(error.message).toLowerCase().includes("unique")) {
      return fail(res, 409, "You have already voted for this position.");
    }

    fail(res, 500, "Could not submit your vote.");
  }
});

// --------------------------------------------------
// ADMIN ONLY: ELECTION RESULTS
// --------------------------------------------------

app.get("/api/results", requireAdmin, (req, res) => {
  const results = all(`
    SELECT
      p.id AS position_id,
      p.title AS position_title,
      c.id AS candidate_id,
      c.full_name AS candidate_name,
      COUNT(v.id) AS votes
    FROM positions p
    LEFT JOIN candidates c ON c.position_id = p.id
    LEFT JOIN votes v ON v.candidate_id = c.id
    GROUP BY p.id, c.id
    ORDER BY p.sort_order, votes DESC, c.full_name
  `);

  res.json(results);
});

// --------------------------------------------------
// ADMIN ONLY: DASHBOARD SUMMARY
// --------------------------------------------------

app.get("/api/admin/summary", requireAdmin, (req, res) => {
  const totalVoters = Number(
    one("SELECT COUNT(*) AS total FROM voters").total
  );

  const totalCandidates = Number(
    one("SELECT COUNT(*) AS total FROM candidates").total
  );

  const totalPositions = Number(
    one("SELECT COUNT(*) AS total FROM positions").total
  );

  const totalVotes = Number(
    one("SELECT COUNT(*) AS total FROM votes").total
  );

  const programStats = PROGRAMS.map(program => ({
    program,
    voters: Number(
      one(
        "SELECT COUNT(*) AS total FROM voters WHERE program = ?",
        [program]
      ).total
    ),
    votes: Number(
      one(
        `SELECT COUNT(v.id) AS total
         FROM voters voter
         LEFT JOIN votes v ON v.voter_id = voter.id
         WHERE voter.program = ?`,
        [program]
      ).total
    )
  }));

  const voteCounts = programStats.map(item => item.votes);
  const maxVotes = Math.max(0, ...voteCounts);
  const minVotes = Math.min(...voteCounts);

  res.json({
    totalVoters,
    totalCandidates,
    totalPositions,
    totalVotes,
    programStats,
    highestProgram: programStats.filter(item => item.votes === maxVotes),
    lowestProgram: programStats.filter(item => item.votes === minVotes)
  });
});

// --------------------------------------------------
// ADMIN ONLY: VOTERS
// --------------------------------------------------

app.get("/api/admin/voters", requireAdmin, (req, res) => {
  res.json(all(`
    SELECT
      id,
      full_name,
      username,
      school_id_number,
      program,
      has_voted,
      created_at
    FROM voters
    ORDER BY id DESC
  `));
});

// --------------------------------------------------
// ADMIN ONLY: ALL ACTIVITY LOGS
// --------------------------------------------------

app.get("/api/admin/activity-logs", requireAdmin, (req, res) => {
  res.json(all(`
    SELECT id, actor, action, created_at
    FROM activity_logs
    ORDER BY id DESC
    LIMIT 200
  `));
});

// --------------------------------------------------
// VOTER ONLY: PERSONAL ACTIVITY LOGS
// --------------------------------------------------

app.get("/api/voter/activity-logs", requireVoter, (req, res) => {
  const schoolId = req.session.account.schoolIdNumber;

  const logs = all(`
    SELECT id, actor, action, created_at
    FROM activity_logs
    WHERE actor = ?
    ORDER BY id DESC
    LIMIT 200
  `, [schoolId]);

  res.json(logs);
});

// --------------------------------------------------
// UNKNOWN API ROUTES
// --------------------------------------------------

app.use("/api", (req, res) => {
  fail(res, 404, "API route not found.");
});

// --------------------------------------------------
// START SERVER
// --------------------------------------------------

async function startServer() {
  const initialized = await initializeDatabase();

  db = initialized.db;
  saveDatabase = initialized.saveDatabase;

  app.listen(PORT, () => {
    console.log("------------------------------------");
    console.log("SJCB Online Voting System");
    console.log("Database initialized successfully.");
    console.log(`Running at http://localhost:${PORT}`);
    console.log("Default admin: admin / Admin123!");
    console.log("------------------------------------");
  });
}

startServer().catch(error => {
  console.error("Server startup failed:", error);
  process.exit(1);
});
