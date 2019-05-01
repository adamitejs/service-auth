const { server } = require('@adamite/relay');
const AuthCommands = require('./AuthCommands');

class AuthService {
  constructor(config) {
    this.config = config;
    this.server = server({ apiUrl: 'http://localhost:9000', port: 9001 });
    this.commands = new AuthCommands(this);
    this.registerCommands();
  }

  registerCommands() {
    // this.server.command(
    //   'database.createDocument',
    //   this.commands.createDocument.bind(this.commands)
    // );
  }

  start() {
    this.server.start();
  }
}

module.exports = AuthService;