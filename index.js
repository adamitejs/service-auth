const AuthService = require("./src/AuthService");

module.exports = function(config, rootConfig) {
  const service = new AuthService(config, rootConfig);
  service.start();
  return service;
};
