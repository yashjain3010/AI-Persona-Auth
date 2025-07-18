async function getOrCreateWorkspace(tx, domain, name = null) {
  let workspace = await tx.workspace.findUnique({ where: { domain } });
  if (!workspace) {
    workspace = await tx.workspace.create({
      data: { name: name || domain, domain },
    });
  }
  return workspace;
}

function assignMembershipRole(isFirstUser) {
  return isFirstUser ? 'ADMIN' : 'MEMBER';
}

module.exports = {
  getOrCreateWorkspace,
  assignMembershipRole,
};
