module.exports = {
  context: {
    repo: { owner: 'test-owner', repo: 'test-repo' },
    runId: 12345,
    serverUrl: 'https://github.com'
  },
  getOctokit: jest.fn()
}
