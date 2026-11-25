/* =========================================================
   CampusConnect - BACK-END (Node.js, no external packages)
   - REST API   : /api/...
   - Database   : data/db.json (created automatically)
   - Auth       : signed token (HMAC) + hashed passwords (scrypt)
   - Front-end  : served from the /public folder
   Run:  node server.js     then open  http://localhost:3000
   ========================================================= */
const http = require("http");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

const PORT = process.env.PORT || 3000;
const DATA_DIR = path.join(__dirname, "data");
const DB_FILE = path.join(DATA_DIR, "db.json");
const PUBLIC_DIR = path.join(__dirname, "public");

/* ---------- Helpers ---------- */
class HttpError extends Error {
  constructor(status, message) {
    super(message);
    this.status = status;
  }
}
const uid = () => crypto.randomBytes(6).toString("hex");
const today = () => new Date().toISOString().slice(0, 10);
const str = (v) => String(v ?? "").trim();

/* ---------- Password hashing ---------- */
function hashPw(pw) {
  const salt = crypto.randomBytes(16).toString("hex");
  return salt + ":" + crypto.scryptSync(pw, salt, 64).toString("hex");
}
function checkPw(pw, stored) {
  const [salt, hash] = stored.split(":");
  const test = crypto.scryptSync(pw, salt, 64);
  return crypto.timingSafeEqual(test, Buffer.from(hash, "hex"));
}

/* ---------- Tiny JSON database ---------- */
function loadDB() {
  if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR);
  if (!fs.existsSync(DB_FILE)) {
    const fresh = {
      secret: crypto.randomBytes(32).toString("hex"),
      users: [{ id: uid(), name: "Admin", email: "admin@campus.com", password: hashPw("admin123"), role: "admin" }],
      rooms: ["Room A101", "Room A102", "Library Hall", "Computer Lab 3"],
      notes: [],
      events: [],
      bookings: [],
    };
    fs.writeFileSync(DB_FILE, JSON.stringify(fresh, null, 2));
  }
  return JSON.parse(fs.readFileSync(DB_FILE, "utf8"));
}
const db = loadDB();
const save = () => fs.writeFileSync(DB_FILE, JSON.stringify(db, null, 2));

/* ---------- Tokens (login sessions) ---------- */
const b64 = (s) => Buffer.from(s).toString("base64url");
const sign = (data) => crypto.createHmac("sha256", db.secret).update(data).digest("base64url");
function makeToken(userId) {
  const body = b64(JSON.stringify({ id: userId, exp: Date.now() + 7 * 24 * 3600 * 1000 }));
  return body + "." + sign(body);
}
function readToken(token) {
  const [body, sig] = String(token || "").split(".");
  if (!body || !sig || sign(body) !== sig) return null;
  const data = JSON.parse(Buffer.from(body, "base64url").toString());
  return data.exp > Date.now() ? data : null;
}
const publicUser = ({ password, ...u }) => u;

/* ---------- Routing ---------- */
const routes = [];
function route(method, pattern, auth, handler) {
  const keys = [];
  const regex = new RegExp("^" + pattern.replace(/:(\w+)/g, (_, k) => (keys.push(k), "([^/]+)")) + "$");
  routes.push({ method, regex, keys, auth, handler });
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    let size = 0;
    const chunks = [];
    req.on("data", (c) => {
      size += c.length;
      if (size > 3 * 1024 * 1024) {
        reject(new HttpError(413, "Request too large (max 3 MB)"));
        req.destroy();
      } else chunks.push(c);
    });
    req.on("end", () => {
      try {
        resolve(chunks.length ? JSON.parse(Buffer.concat(chunks).toString()) : {});
      } catch {
        reject(new HttpError(400, "Invalid JSON"));
      }
    });
  });
}

function send(res, status, obj) {
  res.writeHead(status, { "Content-Type": "application/json" });
  res.end(JSON.stringify(obj));
}

async function handleApi(req, res, pathname) {
  const r = routes.find((x) => x.method === req.method && x.regex.test(pathname));
  if (!r) throw new HttpError(404, "API route not found");
  const match = pathname.match(r.regex);
  const params = Object.fromEntries(r.keys.map((k, i) => [k, decodeURIComponent(match[i + 1])]));

  let user = null;
  if (r.auth !== "none") {
    const token = (req.headers.authorization || "").replace("Bearer ", "");
    const data = readToken(token);
    user = data && db.users.find((u) => u.id === data.id);
    if (!user) throw new HttpError(401, "Please login again");
    if (r.auth === "admin" && user.role !== "admin") throw new HttpError(403, "Admin access only");
  }
  const body = req.method === "GET" || req.method === "DELETE" ? {} : await readBody(req);
  send(res, 200, await r.handler({ user, params, body }));
}

/* =========================================================
   API ROUTES
   ========================================================= */

/* ----- Auth ----- */
route("POST", "/api/signup", "none", ({ body }) => {
  const name = str(body.name);
  const email = str(body.email).toLowerCase();
  const password = String(body.password || "");
  if (!name || !email || password.length < 6) throw new HttpError(400, "Name, email and a password (min 6 chars) are required");
  if (db.users.some((u) => u.email === email)) throw new HttpError(409, "Email already registered");
  db.users.push({ id: uid(), name, email, password: hashPw(password), role: "student" });
  save();
  return { message: "Account created" };
});

route("POST", "/api/login", "none", ({ body }) => {
  const user = db.users.find((u) => u.email === str(body.email).toLowerCase());
  if (!user || !checkPw(String(body.password || ""), user.password)) throw new HttpError(401, "Invalid email or password");
  return { token: makeToken(user.id), user: publicUser(user) };
});

route("GET", "/api/me", "user", ({ user }) => ({ user: publicUser(user) }));

/* ----- Dashboard ----- */
route("GET", "/api/dashboard", "user", ({ user }) => {
  const upcoming = db.events.filter((e) => e.date >= today()).sort((a, b) => a.date.localeCompare(b.date)).slice(0, 3);
  const myBookings = db.bookings.filter((b) => b.userId === user.id);
  return {
    notes: db.notes.filter((n) => n.status === "approved").length,
    events: db.events.length,
    myRsvps: db.events.filter((e) => e.attendees.includes(user.id)).length,
    myBookings: myBookings.length,
    upcoming,
    recentBookings: myBookings.slice(-4),
  };
});

/* ----- Notes ----- */
route("GET", "/api/notes", "user", ({ user }) =>
  db.notes
    .filter((n) => n.status === "approved" || n.userId === user.id || user.role === "admin")
    .map(({ fileData, ...n }) => ({ ...n, hasFile: !!fileData }))
);

route("POST", "/api/notes", "user", ({ user, body }) => {
  const title = str(body.title), subject = str(body.subject), semester = str(body.semester), description = str(body.description);
  if (!title || !subject || !semester || !description) throw new HttpError(400, "All note fields are required");
  if (body.fileData && String(body.fileData).length > 2.2 * 1024 * 1024) throw new HttpError(413, "File too large (max 1.5 MB)");
  db.notes.unshift({
    id: uid(), title, subject, semester, description,
    userId: user.id, userName: user.name, date: today(),
    status: user.role === "admin" ? "approved" : "pending",
    fileData: body.fileData || null, fileName: body.fileName || null,
  });
  save();
  return { message: user.role === "admin" ? "Note published!" : "Note submitted for approval" };
});

route("GET", "/api/notes/:id/file", "user", ({ user, params }) => {
  const n = db.notes.find((x) => x.id === params.id);
  if (!n || !n.fileData) throw new HttpError(404, "File not found");
  if (n.status !== "approved" && n.userId !== user.id && user.role !== "admin") throw new HttpError(403, "Not allowed");
  return { fileName: n.fileName, fileData: n.fileData };
});

route("POST", "/api/notes/:id/approve", "admin", ({ params }) => {
  const n = db.notes.find((x) => x.id === params.id);
  if (!n) throw new HttpError(404, "Note not found");
  n.status = "approved";
  save();
  return { message: "Note approved" };
});

route("DELETE", "/api/notes/:id", "user", ({ user, params }) => {
  const n = db.notes.find((x) => x.id === params.id);
  if (!n) throw new HttpError(404, "Note not found");
  if (n.userId !== user.id && user.role !== "admin") throw new HttpError(403, "Not allowed");
  db.notes = db.notes.filter((x) => x.id !== params.id);
  save();
  return { message: "Note deleted" };
});

/* ----- Events ----- */
route("GET", "/api/events", "user", ({ user }) =>
  db.events
    .slice()
    .sort((a, b) => a.date.localeCompare(b.date))
    .map((e) => ({
      id: e.id, title: e.title, location: e.location, date: e.date, time: e.time,
      capacity: e.capacity, description: e.description,
      count: e.attendees.length,
      going: e.attendees.includes(user.id),
      attendees: user.role === "admin" ? e.attendees.map((id) => db.users.find((u) => u.id === id)?.name).filter(Boolean) : [],
    }))
);

route("POST", "/api/events", "admin", ({ body }) => {
  const title = str(body.title), location = str(body.location), description = str(body.description);
  const capacity = Number(body.capacity);
  if (!title || !location || !description || !body.date || !body.time || !(capacity >= 1)) throw new HttpError(400, "All event fields are required");
  db.events.push({ id: uid(), title, location, description, date: body.date, time: body.time, capacity, attendees: [] });
  save();
  return { message: "Event posted!" };
});

route("POST", "/api/events/:id/rsvp", "user", ({ user, params }) => {
  if (user.role === "admin") throw new HttpError(403, "Only students can RSVP");
  const e = db.events.find((x) => x.id === params.id);
  if (!e) throw new HttpError(404, "Event not found");
  const i = e.attendees.indexOf(user.id);
  if (i >= 0) {
    e.attendees.splice(i, 1);
    save();
    return { message: "RSVP cancelled" };
  }
  if (e.date < today()) throw new HttpError(400, "This event is over");
  if (e.attendees.length >= e.capacity) throw new HttpError(400, "Event is full");
  e.attendees.push(user.id);
  save();
  return { message: "You're going! 🎉" };
});

route("DELETE", "/api/events/:id", "admin", ({ params }) => {
  db.events = db.events.filter((e) => e.id !== params.id);
  save();
  return { message: "Event deleted" };
});

/* ----- Rooms & bookings ----- */
route("GET", "/api/rooms", "user", () => db.rooms);

route("GET", "/api/bookings", "user", ({ user }) =>
  db.bookings
    .filter((b) => user.role === "admin" || b.userId === user.id)
    .sort((a, b) => (a.date + a.start).localeCompare(b.date + b.start))
);

route("POST", "/api/bookings", "user", ({ user, body }) => {
  const { room, date, start, end } = body;
  if (!db.rooms.includes(room) || !date || !start || !end) throw new HttpError(400, "Room, date, start and end are required");
  if (start >= end) throw new HttpError(400, "End time must be after start time");
  // Conflict check: same room + same date + overlapping times
  const clash = db.bookings.find((b) => b.room === room && b.date === date && start < b.end && end > b.start);
  if (clash) throw new HttpError(409, `Conflict! ${room} is booked ${clash.start}-${clash.end}`);
  db.bookings.push({ id: uid(), room, date, start, end, userId: user.id, userName: user.name });
  save();
  return { message: "Room booked successfully ✅" };
});

route("DELETE", "/api/bookings/:id", "user", ({ user, params }) => {
  const b = db.bookings.find((x) => x.id === params.id);
  if (!b) throw new HttpError(404, "Booking not found");
  if (b.userId !== user.id && user.role !== "admin") throw new HttpError(403, "Not allowed");
  db.bookings = db.bookings.filter((x) => x.id !== params.id);
  save();
  return { message: "Booking cancelled" };
});

/* ----- Admin ----- */
route("GET", "/api/admin/stats", "admin", () => ({
  users: db.users.length,
  notes: db.notes.length,
  pending: db.notes.filter((n) => n.status === "pending").length,
  events: db.events.length,
  bookings: db.bookings.length,
}));

route("GET", "/api/admin/users", "admin", () => db.users.map(publicUser));

route("DELETE", "/api/admin/users/:id", "admin", ({ user, params }) => {
  if (params.id === user.id) throw new HttpError(400, "You cannot remove yourself");
  db.users = db.users.filter((u) => u.id !== params.id);
  db.notes = db.notes.filter((n) => n.userId !== params.id);
  db.bookings = db.bookings.filter((b) => b.userId !== params.id);
  db.events.forEach((e) => (e.attendees = e.attendees.filter((a) => a !== params.id)));
  save();
  return { message: "User removed" };
});

/* ---------- Static files (front-end) ---------- */
const MIME = {
  ".html": "text/html", ".css": "text/css", ".js": "text/javascript", ".json": "application/json",
  ".png": "image/png", ".jpg": "image/jpeg", ".jpeg": "image/jpeg", ".svg": "image/svg+xml", ".ico": "image/x-icon",
};
function serveStatic(res, pathname) {
  const rel = pathname === "/" ? "/index.html" : pathname;
  const file = path.normalize(path.join(PUBLIC_DIR, rel));
  if (!file.startsWith(PUBLIC_DIR) || !fs.existsSync(file) || fs.statSync(file).isDirectory()) {
    res.writeHead(404, { "Content-Type": "text/plain" });
    return res.end("Not found");
  }
  res.writeHead(200, { "Content-Type": MIME[path.extname(file)] || "application/octet-stream" });
  fs.createReadStream(file).pipe(res);
}

/* ---------- Start server ---------- */
const server = http.createServer(async (req, res) => {
    try {
      const { pathname } = new URL(req.url, "http://localhost");
      if (pathname.startsWith("/api/")) return await handleApi(req, res, pathname);
      serveStatic(res, pathname);
    } catch (err) {
      const status = err.status || 500;
      if (status === 500) console.error(err);
      if (!res.headersSent) send(res, status, { error: status === 500 ? "Server error" : err.message });
    }
});

// If the port is busy, automatically try the next one (3000, 3001, 3002 ...)
server.on("listening", () => console.log(`CampusConnect running at http://localhost:${server.address().port}`));
function start(port, tries = 0) {
  server.once("error", (err) => {
    if (err.code === "EADDRINUSE" && tries < 10) {
      console.log(`Port ${port} is busy, trying ${port + 1}...`);
      start(port + 1, tries + 1);
    } else throw err;
  });
  server.listen(port);
}
start(Number(PORT));
