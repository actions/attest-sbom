module.exports = {
  context: {
    repo: { owner: 'test-owner', repo: 'test-repo' },
    runId: 12345,
    workflow: 'ci.yml'
  },
  getOctokit: jest.fn()
}
