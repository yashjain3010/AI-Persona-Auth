const {
  sendVerificationEmail,
  sendWelcomeEmail,
  sendPasswordResetEmail,
  sendInvitationEmail,
  sendSecurityAlertEmail,
} = require('../config/email');

async function sendUserEmail(type, params) {
  switch (type) {
    case 'verification':
      return await sendVerificationEmail(params);
    case 'welcome':
      return await sendWelcomeEmail(params);
    case 'passwordReset':
      return await sendPasswordResetEmail(params);
    case 'invitation':
      return await sendInvitationEmail(params);
    case 'securityAlert':
      return await sendSecurityAlertEmail(params);
    default:
      throw new Error('Unknown email type');
  }
}

module.exports = { sendUserEmail };
