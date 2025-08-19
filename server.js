"use strict";

const express = require("express");
const favicon = require("serve-favicon");
const bodyParser = require("body-parser");
const session = require("express-session");
const consolidate = require("consolidate");
const swig = require("swig");
const helmet = require("helmet");
const MongoClient = require("mongodb").MongoClient;
const marked = require("marked");
const fs = require("fs");
const https = require("https");
const path = require("path");
const winston = require("winston");
const rateLimit = require("express-rate-limit");
const cors = require("cors");

const app = express();

app.use(helmet.hsts({ maxAge: 31536000 })); // enforce HTTPS for 1 year


app.use(
  helmet.contentSecurityPolicy({
    useDefaults: true,
    directives: {
      "default-src": ["'self'"], // only allow resources from your own server
      "script-src": ["'self'"], // only allow JS from your domain
      "style-src": ["'self'", "https://fonts.googleapis.com"], // allow styles + Google Fonts
      "font-src": ["'self'", "https://fonts.gstatic.com"], // allow fonts
    },
  })
);


// Define some valid API keys (normally stored in DB or env variable)
const API_KEYS = ["abc123xyz", "def456uvw"];

// Middleware function to check key
function checkApiKey(req, res, next) {
  const apiKey = req.headers["x-api-key"]; // read from request header
  if (API_KEYS.includes(apiKey)) {
    next(); // ✅ valid, move to next handler
  } else {
    res.status(401).json({ message: "Unauthorized: Invalid API Key" });
  }
}

// Example protected route
app.get("/secure-data", checkApiKey, (req, res) => {
  res.json({ secret: "This is protected data only visible with a valid key" });
});


const allowedOrigins = ["https://localhost:4000", "https://yourfrontend.com"];

app.use(cors({
  origin: function (origin, callback) {
    if (!origin || allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error("Not allowed by CORS"));
    }
  },
  methods: ["GET", "POST", "PUT", "DELETE"],
  credentials: true
}));




const limiter = rateLimit({
  windowMs: 1 * 60 * 1000, // 15 minutes
  max: 100, 
  message: "Too many requests from this IP, please try again later."
});

app.use(limiter); 


// Winston logger configuration (plain text for Fail2Ban)
const logger = winston.createLogger({
    level: "info",
    format: winston.format.printf(({ level, message }) => {
        return `${new Date().toISOString()} ${level.toUpperCase()} ${message}`;
    }),
    transports: [
        new winston.transports.Console(),
        new winston.transports.File({ filename: path.join(__dirname, "security.log") })
    ]
});

logger.info("Application started");
app.use(helmet());

// Track failed login attempts per IP
let failedLoginAttempts = {};

// Middleware to log all incoming requests
app.use((req, res, next) => {
    logger.info(`Incoming request from ${req.ip} to ${req.method} ${req.originalUrl}`);
    next();
});

const routes = require("./app/routes");
const { port, db, cookieSecret } = require("./config/config");

const httpsOptions = {
    key: fs.readFileSync(path.resolve(__dirname, "./artifacts/cert/server.key")),
    cert: fs.readFileSync(path.resolve(__dirname, "./artifacts/cert/server.crt")),
};

MongoClient.connect(db, (err, db) => {
    if (err) {
        logger.error(`Error connecting to MongoDB: ${err.message}`);
        process.exit(1);
    }
    logger.info("Connected to MongoDB");

    app.use(favicon(__dirname + "/app/assets/favicon.ico"));
    app.use(bodyParser.json());
    app.use(bodyParser.urlencoded({ extended: false }));

    app.use(session({
        secret: cookieSecret,
        saveUninitialized: true,
        resave: true
    }));

    app.engine(".html", consolidate.swig);
    app.set("view engine", "html");
    app.set("views", `${__dirname}/app/views`);
    app.use(express.static(`${__dirname}/app/assets`));

    marked.setOptions({ sanitize: true });
    app.locals.marked = marked;

    // Example login route for Fail2Ban
    app.post("/login", async (req, res) => {
    const { username, password } = req.body;
    const ip = req.ip;

    try {
        const user = await db.collection("users").findOne({ username });

        if (!user || user.password !== password) {
            failedLoginAttempts[ip] = (failedLoginAttempts[ip] || 0) + 1;
            logger.warn(`Failed login attempt for user '${username}' from ${ip}`);

            if (failedLoginAttempts[ip] >= 3) {
                logger.error(`Multiple failed login attempts from ${ip} - possible brute force`);
            }

            return res.status(401).send("Unauthorized");
        }

        failedLoginAttempts[ip] = 0;
        logger.info(`Successful login for user '${username}' from ${ip}`);
        res.send("Login successful!");
    } catch (err) {
        logger.error("Database error during login:", err);
        res.status(500).send("Internal server error");
    }
});


    routes(app, db);
    swig.setDefaults({ autoescape: false });

    https.createServer(httpsOptions, app).listen(port, () => {
        console.log(`✅ HTTPS server running at https://localhost:${port}`);
    });
});

