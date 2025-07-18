// Utility functions for domain and email handling
const config = require('../config');

function extractDomain(email) {
  return email.split('@')[1];
}

function normalizeEmail(email) {
  return email.toLowerCase().trim();
}

function isPersonalEmail(email) {
  const domain = extractDomain(email);
  return (
    config.workspace?.blockedDomains || [
      'gmail.com',
      'yahoo.com',
      'hotmail.com',
      'outlook.com',
      'aol.com',
      'icloud.com',
    ]
  ).includes(domain);
}

module.exports = {
  extractDomain,
  normalizeEmail,
  isPersonalEmail,
};
