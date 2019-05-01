const AuthService = require('./src/AuthService');

module.exports = function(config) {
  const service = new AuthService(config);
  service.start();
  return service;
};