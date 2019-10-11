const fs = require("fs");
const bcrypt = require("bcrypt");
const uuid = require("uuid");
const low = require("lowdb");
const FileSync = require("lowdb/adapters/FileSync");
const server = require("@adamite/relay-server").default;
const jwt = require("jsonwebtoken");
const AuthCommands = require("./AuthCommands");

class AuthService {
  constructor(config) {
    this.config = config;
    this.server = server(
      { name: "auth", apiUrl: this.config.apiUrl || "http://localhost:9000", port: this.config.port || 9002 },
      this.config
    );
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
    this.server.command("auth.loginWithEmailAndPassword", async (client, args, callback) => {
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
          this.config.secret,
          { expiresIn: "1d" }
        );

        users
          .find({ id: user.id })
          .update("loginCount", n => (n || 0) + 1)
          .set("lastLoginAt", Date.now())
          .set("lastLoginIP", client.socket.handshake.address)
          .write();

        callback({ error: false, token });
      } catch (err) {
        console.error(err);
        callback({ error: err.message });
      }
    });

    this.server.command("auth.createUser", async (client, args, callback) => {
      try {
        const { email, password } = args;
        this._checkForExistingUser(email);

        const user = {
          id: uuid.v4(),
          email: args.email,
          password: await bcrypt.hash(password, 10),
          createdAt: Date.now(),
          lastLoginAt: Date.now(),
          lastLoginIP: client.socket.handshake.address,
          loginCount: args.bypassLogin ? 0 : 1
        };

        const users = this.db.get("users");
        users.push(user).write();

        const token = jwt.sign(
          {
            sub: user.id,
            email: user.email
          },
          this.config.secret,
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
        const data = jwt.verify(args.token, this.config.secret);
        callback({ error: false, data });
      } catch (err) {
        console.error(err);
        callback({ error: err.message });
      }
    });

    this.server.command("auth.admin.getUsers", (client, args, callback) => {
      try {
        this._verifyAdminAccess(client);
        const users = this.db.get("users").map(u => {
          return { ...u, password: undefined };
        });
        callback({ error: false, users });
      } catch (err) {
        console.error(err);
        callback({ error: err.message });
      }
    });

    this.server.command("auth.admin.getUserInfo", (client, args, callback) => {
      try {
        this._verifyAdminAccess(client);

        const userInfo = this.db
          .get("users")
          .find({ id: args.userId })
          .value();

        callback({
          error: false,
          userInfo: {
            ...userInfo,
            password: undefined
          }
        });
      } catch (err) {
        console.error(err);
        callback({ error: err.message });
      }
    });

    this.server.command("auth.admin.setUserEmail", (client, args, callback) => {
      try {
        this._verifyAdminAccess(client);

        this.db
          .get("users")
          .find({ id: args.userId })
          .set("email", args.email)
          .write();

        callback({ error: false });
      } catch (err) {
        console.error(err);
        callback({ error: err.message });
      }
    });

    this.server.command("auth.admin.setUserPassword", async (client, args, callback) => {
      try {
        this._verifyAdminAccess(client);

        this.db
          .get("users")
          .find({ id: args.userId })
          .set("password", await bcrypt.hash(args.password, 10))
          .write();

        callback({ error: false });
      } catch (err) {
        console.error(err);
        callback({ error: err.message });
      }
    });

    this.server.command("auth.admin.setUserDisabled", (client, args, callback) => {
      try {
        this._verifyAdminAccess(client);

        this.db
          .get("users")
          .find({ id: args.userId })
          .set("disabled", args.disabled)
          .write();

        callback({ error: false });
      } catch (err) {
        console.error(err);
        callback({ error: err.message });
      }
    });

    this.server.command("auth.admin.deleteUser", (client, args, callback) => {
      try {
        this._verifyAdminAccess(client);

        this.db
          .get("users")
          .remove({ id: args.userId })
          .write();

        callback({ error: false });
      } catch (err) {
        console.error(err);
        callback({ error: err.message });
      }
    });
  }

  start() {
    this.server.start();
  }

  _verifyAdminAccess(client) {
    if (!client.socket.request._query.secret) throw new Error("Admin commands require secret authentication.");
  }

  _checkForExistingUser(email) {
    const user = this.db
      .get("users")
      .find(u => u.email === email)
      .value();
    if (!!user) throw new Error("A user with that email address already exists.");
  }
}

module.exports = AuthService;
