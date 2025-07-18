const {
  sendVerificationEmail,
  sendWelcomeEmail,
  sendPasswordResetEmail,
  sendInvitationEmail,
  sendSecurityAlertEmail,
} = require('../config/email');
const { ApiError } = require('./apiError');

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
      throw new ApiError(
        400,
        `Unknown email type: ${type}`,
        'EMAIL_TYPE_INVALID',
      );
  }
}

module.exports = { sendUserEmail };
