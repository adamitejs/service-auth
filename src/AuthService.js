const fs = require("fs");
const bcrypt = require("bcrypt");
const uuid = require("uuid");
const low = require("lowdb");
const FileSync = require("lowdb/adapters/FileSync");
const { server } = require("@adamite/relay");
const jwt = require("jsonwebtoken");
const AuthCommands = require("./AuthCommands");

class AuthService {
  constructor(config) {
    this.config = config;
    this.server = server({ apiUrl: "http://localhost:9000", port: 9002 });
    this.commands = new AuthCommands(this);
    this.initializeDatabase();
    this.registerCommands();
  }

  initializeDatabase() {
    if (!fs.existsSync("data")) fs.mkdirSync("data");
    this.db = low(new FileSync("data/auth.json"));
    this.db.defaults({ users: [] }).write();
  }

  registerCommands() {
    this.server.command(
      "auth.loginWithEmailAndPassword",
      async (client, args, callback) => {
        try {
          const { email, password } = args;
          const users = this.db.get("users");
          const user = users.find(u => u.email === email).value();

          if (!user) {
            throw new Error("Invalid email or password.");
          }

          if (user.disabled) {
            throw new Error("User is disabled.");
          }

          if (!(await bcrypt.compare(password, user.password))) {
            throw new Error("Invalid email or password.");
          }

          const token = jwt.sign(
            {
              sub: user.id,
              email: user.email
            },
            this.config.auth.secret,
            { expiresIn: "1d" }
          );

          callback({ error: false, token });
        } catch (err) {
          console.error(err);
          callback({ error: err.message });
        }
      }
    );

    this.server.command("auth.createUser", async (client, args, callback) => {
      try {
        const { email, password } = args;
        this._checkForExistingUser(email);

        const user = {
          id: uuid.v4(),
          email: args.email,
          password: await bcrypt.hash(password, 10)
        };

        const users = this.db.get("users");
        users.push(user).write();

        const token = jwt.sign(
          {
            sub: user.id,
            email: user.email
          },
          this.config.auth.secret,
          { expiresIn: "1d" }
        );

        callback({ error: false, token });
      } catch (err) {
        console.error(err);
        callback({ error: err.message });
      }
    });

    this.server.command("auth.validateToken", (client, args, callback) => {
      try {
        const data = jwt.verify(args.token, this.config.auth.secret);
        callback({ error: false, data });
      } catch (err) {
        console.error(err);
        callback({ error: err.message });
      }
    });
  }

  start() {
    this.server.start();
  }

  _checkForExistingUser(email) {
    const user = this.db
      .get("users")
      .find(u => u.email === email)
      .value();
    if (!!user)
      throw new Error("A user with that email address already exists.");
  }
}

module.exports = AuthService;
