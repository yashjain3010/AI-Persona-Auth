const bcrypt = require('bcryptjs');
const crypto = require('crypto');

async function hashPassword(password) {
  const saltRounds = 10; // Or get from config
  return await bcrypt.hash(password, saltRounds);
}

async function comparePassword(password, hash) {
  return await bcrypt.compare(password, hash);
}

function generateSecureToken(length = 48) {
  return crypto.randomBytes(length).toString('hex');
}

module.exports = {
  hashPassword,
  comparePassword,
  generateSecureToken,
};
